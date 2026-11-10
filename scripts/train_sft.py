"""H6: generative SFT. Teach Qwen2.5-Coder-7B to answer, for a line-numbered code region, either
{"findings":[{"line":L,"cwe":"CWE-x","title":...}]} (vulnerable version) or {"findings":[]} (patched version /
far region). LoRA, loss on the answer tokens only. Train split only; validation = held-out train repos.

Validation metric (same rules as the bench, region level): pair accuracy = vulnerable region answered with a
finding within +-5 lines of a truth line AND its patched twin answered with nothing within +-5 of the fix site.
The bar to beat is the triage classifier's best held-out pair accuracy (0.56, a different but comparable
pairwise measure).

Shared-box guards as in train_triage.py (memory floor/watchdog, /tmp/detector-gpu.lock, oom_score_adj 900).
"""
from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import pathlib
import random
import re
import sys
import time

import torch
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from train_triage import LOCK, mem_available_gb, split_by_repo  # noqa: E402

BASE = "Qwen/Qwen2.5-Coder-7B-Instruct"
SYSTEM = ("You are a security code reviewer. Given a code region with real line numbers, report the one "
          "vulnerability an attacker could exploit, or nothing if the code is safe. Answer with JSON only: "
          '{"findings": [{"line": <line where the fix must go>, "cwe": "CWE-<n>", "title": "<short>"}]} '
          'or {"findings": []}.')


def prompt_text(r: dict) -> str:
    start = r["span"][0]
    body = "\n".join(f"{start + i:5d}  {l}" for i, l in enumerate(r["text"].splitlines()))
    return f"File: {r['file']}\n```\n{body}\n```"


def target(r: dict) -> str:
    if r["kind"] == "pos":
        title = re.sub(r"\s+", " ", (r.get("summary") or "vulnerability"))[:100]
        return json.dumps({"findings": [{"line": r["truth_lines"][0], "cwe": (r.get("cwes") or ["CWE-20"])[0],
                                         "title": title}]})
    return json.dumps({"findings": []})


def select(rows: list[dict], n_pairs: int, n_far: int, seed: int) -> list[dict]:
    pos = {r["pair"]: r for r in rows if r["kind"] == "pos" and r.get("truth_lines")}
    neg = {r["pair"]: r for r in rows if r["kind"] == "neg"}
    pairs = sorted(k for k in pos if k in neg)
    rng = random.Random(seed)
    rng.shuffle(pairs)
    far = [r for r in rows if r["kind"] == "far"]
    rng.shuffle(far)
    out = [x for k in pairs[:n_pairs] for x in (pos[k], neg[k])] + far[:n_far]
    rng.shuffle(out)
    return out


def encode(tok, r: dict, max_len: int):
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt_text(r)}]
    p_ids = tok(tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False),
                add_special_tokens=False)["input_ids"]
    t_ids = tok(target(r) + tok.eos_token, add_special_tokens=False)["input_ids"]
    if len(p_ids) + len(t_ids) > max_len:
        p_ids = p_ids[: max_len - len(t_ids)]  # truncate the code, never the answer
    return p_ids + t_ids, [-100] * len(p_ids) + t_ids


def parse(text: str) -> list[dict]:
    try:
        obj = json.loads(text[text.find("{"): text.rfind("}") + 1])
        return [f for f in obj.get("findings", []) if isinstance(f, dict)]
    except Exception:  # noqa: BLE001
        return []


def near(fs: list[dict], lines: list[int], w: int = 5) -> bool:
    for f in fs:
        try:
            ln = int(f.get("line"))
        except (TypeError, ValueError):
            continue
        if lines and min(abs(ln - t) for t in lines) <= w:
            return True
    return False


@torch.no_grad()
def validate(model, tok, val_pairs, max_len: int, device: str, bs: int = 8) -> dict:
    model.eval()
    tok.padding_side = "left"
    flat = [r for p in val_pairs for r in p]
    outs = []
    for i in range(0, len(flat), bs):
        chunk = flat[i:i + bs]
        prompts = [tok.apply_chat_template([{"role": "system", "content": SYSTEM},
                                            {"role": "user", "content": prompt_text(r)}],
                                           add_generation_prompt=True, tokenize=False) for r in chunk]
        enc = tok(prompts, return_tensors="pt", padding=True, truncation=True, max_length=max_len - 96).to(device)
        with torch.autocast("cuda", dtype=torch.bfloat16):
            gen = model.generate(**enc, max_new_tokens=96, do_sample=False, pad_token_id=tok.pad_token_id)
        outs += tok.batch_decode(gen[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)
    model.train()
    tok.padding_side = "right"
    res = dict(zip(range(len(flat)), (parse(o) for o in outs)))
    hit = pair_ok = vflag = fflag = 0
    for k, (p, n) in enumerate(val_pairs):
        fp, fn = res[2 * k], res[2 * k + 1]
        h = near(fp, p["truth_lines"]); s = near(fn, n.get("fix_site") or [])
        hit += h; pair_ok += h and not s; vflag += bool(fp); fflag += bool(fn)
    n = max(len(val_pairs), 1)
    return {"pair_acc": pair_ok / n, "recall": hit / n, "vuln_flagged": vflag / n, "patched_flagged": fflag / n,
            "n_pairs": len(val_pairs)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data/train/regions_v2.jsonl"))
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pairs", type=int, default=4000)
    ap.add_argument("--far", type=int, default=400)  # keep pos ~50%: 58% empty targets collapsed the smoke run to "no findings"
    ap.add_argument("--val-pairs", type=int, default=200)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--bs", type=int, default=4)
    ap.add_argument("--accum", type=int, default=8)
    ap.add_argument("--max-len", type=int, default=1536)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--val-every", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--min-free-gb", type=float, default=30.0)
    ap.add_argument("--abort-below-gb", type=float, default=8.0)
    ap.add_argument("--limit", type=int, default=0, help="smoke: cap training examples")
    a = ap.parse_args()

    if mem_available_gb() < a.min_free_gb:
        sys.exit(f"refusing: MemAvailable {mem_available_gb():.1f} GB < {a.min_free_gb} GB")
    lockf = open(LOCK, "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(f"refusing: {LOCK} is held by another GPU job")
    with open(f"/proc/{os.getpid()}/oom_score_adj", "w") as f:
        f.write("900")
    random.seed(a.seed); torch.manual_seed(a.seed)

    rows = [json.loads(l) for l in open(a.data)]
    train_rows, val_rows = split_by_repo(rows, 0.08, a.seed)
    train = select(train_rows, a.pairs, a.far, a.seed)[: a.limit or None]
    vpos = {r["pair"]: r for r in val_rows if r["kind"] == "pos" and r.get("truth_lines")}
    vneg = {r["pair"]: r for r in val_rows if r["kind"] == "neg"}
    vkeys = sorted(k for k in vpos if k in vneg)
    random.Random(a.seed).shuffle(vkeys)
    val_pairs = [(vpos[k], vneg[k]) for k in vkeys[: a.val_pairs if not a.limit else 16]]
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    print(f"train {len(train)} examples, val {len(val_pairs)} pairs; MemAvailable {mem_available_gb():.1f} GB", flush=True)

    device = "cuda"
    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "right"
    model = AutoModelForCausalLM.from_pretrained(a.base, dtype=torch.bfloat16)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(
        r=a.lora_r, lora_alpha=2 * a.lora_r, lora_dropout=0.05, task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]))
    model.print_trainable_parameters()
    model.to(device).train()

    enc = [encode(tok, r, a.max_len) for r in train]
    steps_per_epoch = math.ceil(len(enc) / (a.bs * a.accum))
    total = max(1, int(steps_per_epoch * a.epochs))
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=a.lr)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / max(1, int(0.05 * total))) * 0.5 * (1 + math.cos(math.pi * min(s, total) / total)))
    log = (out / "train_log.jsonl").open("a")
    base_m = validate(model, tok, val_pairs, a.max_len, device)
    print("VAL step 0 (base model)", json.dumps(base_m), flush=True)
    log.write(json.dumps({"step": 0, **base_m}) + "\n"); log.flush()
    best, step, micro, idx, t0 = -1.0, 0, 0, 0, time.time()
    while step < total:
        batch = [enc[(idx + j) % len(enc)] for j in range(a.bs)]
        idx += a.bs
        L = max(len(x) for x, _ in batch)
        ids = torch.tensor([x + [tok.pad_token_id] * (L - len(x)) for x, _ in batch], device=device)
        lab = torch.tensor([y + [-100] * (L - len(y)) for _, y in batch], device=device)
        att = torch.tensor([[1] * len(x) + [0] * (L - len(x)) for x, _ in batch], device=device)
        with torch.autocast("cuda", dtype=torch.bfloat16):
            loss = model(input_ids=ids, attention_mask=att, labels=lab).loss / a.accum
        loss.backward()
        micro += 1
        if micro % a.accum:
            continue
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
        step += 1
        if mem_available_gb() < a.abort_below_gb:
            model.save_pretrained(out / "abort_checkpoint")
            sys.exit(f"MEMORY WATCHDOG: MemAvailable {mem_available_gb():.1f} GB; checkpoint saved")
        if step % 10 == 0:
            print(f"step {step}/{total} loss {loss.item() * a.accum:.4f} {(time.time() - t0) / step:.0f}s/step "
                  f"mem {mem_available_gb():.0f}GB", flush=True)
        if step % a.val_every == 0 or step == total:
            m = validate(model, tok, val_pairs, a.max_len, device)
            m["step"] = step
            print("VAL", json.dumps(m), flush=True)
            log.write(json.dumps(m) + "\n"); log.flush()
            if m["pair_acc"] > best:
                best = m["pair_acc"]
                model.save_pretrained(out / "best"); tok.save_pretrained(out / "best")
    (out / "config.json").write_text(json.dumps({**vars(a), "best_val_pair_acc": best,
                                                 "base_val": base_m}, indent=2))
    print(f"done; best val pair acc {best:.3f} (base model {base_m['pair_acc']:.3f})", flush=True)


if __name__ == "__main__":
    main()
