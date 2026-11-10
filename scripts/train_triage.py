"""U3: fine-tune the triage model (binary: is this code region vulnerable?) with LoRA.

Data: data/train/regions.jsonl (train split only). Validation = ~8% of train repos (repo-disjoint).
Reports val AUC and pairwise accuracy (vulnerable region scores above its own patched version).

Shared-box guards (same rules as /srv/gateway/detector): refuse to start below --min-free-gb
MemAvailable, stop with a checkpoint below --abort-below-gb, oom_score_adj 900, and hold the shared
/tmp/detector-gpu.lock for the whole run (the red-team lab waits on it).
"""
from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import pathlib
import random
import sys
import time

import torch
from peft import LoraConfig, get_peft_model
from sklearn.metrics import roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = "/tmp/detector-gpu.lock"
BASE = "Qwen/Qwen2.5-Coder-1.5B-Instruct"


def mem_available_gb() -> float:
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / 1048576
    return 0.0


def fmt(r: dict) -> str:
    return f"File: {r['file']}\n```\n{r['text']}\n```"


def split_by_repo(rows: list[dict], val_frac: float, seed: int):
    repos = sorted({r["repo"] for r in rows})
    random.Random(seed).shuffle(repos)
    val = set(repos[: max(1, int(len(repos) * val_frac))])
    return [r for r in rows if r["repo"] not in val], [r for r in rows if r["repo"] in val]


@torch.no_grad()
def predict(model, tok, rows, max_len, bs, device) -> list[float]:
    model.eval()
    out = []
    for i in range(0, len(rows), bs):
        batch = tok([fmt(r) for r in rows[i:i + bs]], truncation=True, max_length=max_len, padding=True,
                    return_tensors="pt").to(device)
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(**batch).logits.float()
        out += torch.softmax(logits, -1)[:, 1].tolist()
    model.train()
    return out


def evaluate(model, tok, val, max_len, bs, device) -> dict:
    p = predict(model, tok, val, max_len, bs, device)
    y = [r["label"] for r in val]
    by_pair = {}
    for r, s in zip(val, p):
        if r["pair"]:
            by_pair.setdefault(r["pair"], {})[r["kind"]] = s
    pairs = [v for v in by_pair.values() if "pos" in v and "neg" in v]
    return {"auc": roc_auc_score(y, p) if len(set(y)) > 1 else float("nan"),
            "pairwise_acc": sum(v["pos"] > v["neg"] for v in pairs) / max(len(pairs), 1),
            "pair_both_right@0.5": sum(v["pos"] >= 0.5 > v["neg"] for v in pairs) / max(len(pairs), 1),
            "n_val": len(val), "n_pairs": len(pairs)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data/train/regions.jsonl"))
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--bs", type=int, default=8)
    ap.add_argument("--accum", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--val-frac", type=float, default=0.08)
    ap.add_argument("--eval-every", type=int, default=200, help="optimizer steps")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--min-free-gb", type=float, default=20.0)
    ap.add_argument("--abort-below-gb", type=float, default=8.0)
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
    rows = [r for r in rows if r["text"].strip()]
    train, val = split_by_repo(rows, a.val_frac, a.seed)
    random.Random(a.seed).shuffle(train)
    if a.limit:
        train, val = train[: a.limit], val[: max(64, a.limit // 8)]
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    print(f"train {len(train)} (pos {sum(r['label'] for r in train)}), val {len(val)}; MemAvailable "
          f"{mem_available_gb():.1f} GB", flush=True)

    device = "cuda"
    tok = AutoTokenizer.from_pretrained(a.base)
    tok.padding_side = "left"
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForSequenceClassification.from_pretrained(a.base, num_labels=2, torch_dtype=torch.bfloat16)
    model.config.pad_token_id = tok.pad_token_id
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(
        r=a.lora_r, lora_alpha=2 * a.lora_r, lora_dropout=0.05, task_type="SEQ_CLS",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        modules_to_save=["score"]))
    model.print_trainable_parameters()
    model.to(device).train()

    steps_per_epoch = math.ceil(len(train) / (a.bs * a.accum))
    total = int(steps_per_epoch * a.epochs)
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=a.lr, weight_decay=0.0)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / max(1, int(0.05 * total))) * 0.5 * (1 + math.cos(math.pi * min(s, total) / total)))
    best, step, micro, t0 = -1.0, 0, 0, time.time()
    log = (out / "train_log.jsonl").open("a")
    idx = 0
    while step < total:
        batch_rows = [train[(idx + j) % len(train)] for j in range(a.bs)]
        idx += a.bs
        enc = tok([fmt(r) for r in batch_rows], truncation=True, max_length=a.max_len, padding=True,
                  return_tensors="pt").to(device)
        labels = torch.tensor([r["label"] for r in batch_rows], device=device)
        with torch.autocast("cuda", dtype=torch.bfloat16):
            loss = torch.nn.functional.cross_entropy(model(**enc).logits.float(), labels) / a.accum
        loss.backward()
        micro += 1
        if micro % a.accum:
            continue
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
        step += 1
        if mem_available_gb() < a.abort_below_gb:
            model.save_pretrained(out / "abort_checkpoint")
            sys.exit(f"MEMORY WATCHDOG: MemAvailable {mem_available_gb():.1f} GB < {a.abort_below_gb}; checkpoint saved")
        if step % 20 == 0:
            print(f"step {step}/{total} loss {loss.item() * a.accum:.4f} lr {sched.get_last_lr()[0]:.2e} "
                  f"{(time.time() - t0) / step:.1f}s/step mem {mem_available_gb():.0f}GB", flush=True)
        if step % a.eval_every == 0 or step == total:
            m = evaluate(model, tok, val, a.max_len, a.bs * 2, device)
            m.update(step=step, epoch=step / steps_per_epoch)
            print("EVAL", json.dumps(m), flush=True)
            log.write(json.dumps(m) + "\n"); log.flush()
            if m["pairwise_acc"] > best:
                best = m["pairwise_acc"]
                model.save_pretrained(out / "best")
                tok.save_pretrained(out / "best")
    (out / "config.json").write_text(json.dumps({**vars(a), "best_val_pairwise_acc": best}, indent=2))
    print(f"done; best val pairwise acc {best:.3f}", flush=True)


if __name__ == "__main__":
    main()
