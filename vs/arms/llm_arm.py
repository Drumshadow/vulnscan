"""Single-shot LLM arm over an OpenAI-compatible endpoint (vLLM :8000, llama.cpp :8082)."""
from __future__ import annotations

import json
import urllib.request

from ..prompt import SYSTEM, build_user, parse_findings

PROFILES = {
    # Qwen3.6 35B on vLLM, thinking on (Qwen advises against greedy decoding in thinking mode).
    "qwen35b": {"base": "http://127.0.0.1:8000/v1", "model": "qwen3.6-35b-a3b", "budget_chars": 90000,
                "params": {"temperature": 0.6, "top_p": 0.95, "max_tokens": 16384, "seed": 1729,
                           "chat_template_kwargs": {"enable_thinking": True}}},
    # Abliterated 35B (qwen3.6-35b-a3b-uncensored-nvfp4), served in place of the stock model during the
    # overnight window (scripts/abliterated_window.sh). Same params as qwen35b. Its NVFP4 recipe keeps
    # attention in FP8, so a difference vs qwen35b mixes abliteration and quantization.
    "qwen35b_abl": {"base": "http://127.0.0.1:8000/v1", "model": "qwen3.6-35b-a3b-abliterated", "budget_chars": 90000,
                    "params": {"temperature": 0.6, "top_p": 0.95, "max_tokens": 16384, "seed": 1729,
                               "chat_template_kwargs": {"enable_thinking": True}}},
    # DeepHat-V1-7B on llama.cpp, 16k context. Code tokenizes at ~2.5 chars/token, so 20k chars in
    # (+ system prompt) leaves room for 3k tokens out. 36k overflowed on 80% of items.
    "deephat": {"base": "http://127.0.0.1:8082/v1", "model": "deephat", "budget_chars": 20000,
                "params": {"temperature": 0.2, "top_p": 0.95, "max_tokens": 3072, "seed": 1729}},
}


def make_review(profile: str):
    p = PROFILES[profile]

    def review(item: dict):
        body = {"model": p["model"], "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": build_user(item, p["budget_chars"])}], **p["params"]}
        req = urllib.request.Request(f"{p['base']}/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=1800) as r:
            resp = json.load(r)
        msg = resp["choices"][0]["message"]
        content = msg.get("content") or ""
        usage = resp.get("usage") or {}
        meta = {"tokens_in": usage.get("prompt_tokens"), "tokens_out": usage.get("completion_tokens"),
                "raw": content[:20000]}
        if resp["choices"][0].get("finish_reason") == "length" and "{" not in content:
            raise RuntimeError("hit max_tokens before answering")
        return parse_findings(content), meta

    return review


def config(profile: str) -> dict:
    p = PROFILES[profile]
    return {"tool": "llm-single-shot", "profile": profile, "model": p["model"], "params": p["params"],
            "budget_chars": p["budget_chars"], "prompt": "vs/prompt.py@v1+nc-v2-redact"}
