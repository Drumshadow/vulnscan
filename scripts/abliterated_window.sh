#!/usr/bin/env bash
# Overnight window: swap the abliterated 35B into vLLM :8000, run it on the frontier samples
# (new-code framing first: the headline), then swap the stock model back.
# The stock vllm-main.service is ALWAYS restored (trap), then verified with a real completion.
set -euo pipefail
cd /srv/gateway/vulnscan
log() { echo "[$(date -Is)] $*"; }

restore() {
  log "restoring stock vLLM"
  systemctl --user stop vllm-abliterated 2>/dev/null || true
  systemctl --user reset-failed vllm-abliterated 2>/dev/null || true
  sudo -n systemctl start vllm-main
  for i in $(seq 1 120); do
    if curl -sf localhost:8000/v1/models | grep -q '"qwen3.6-35b-a3b"'; then break; fi; sleep 10
  done
  reply=$(curl -s localhost:8000/v1/chat/completions -H 'Content-Type: application/json' \
    -d '{"model":"qwen3.6-35b-a3b","messages":[{"role":"user","content":"Reply with the word READY."}],"max_tokens":20,"chat_template_kwargs":{"enable_thinking":false}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["choices"][0]["message"]["content"])' || echo FAILED)
  log "stock model check: $reply"
}

# Wait until no eval that needs the stock vllm-main is running (qwen35b single-shot and the harness).
# Match on the python argv only, never on a shell command line.
busy() { ps -eo args | grep -E '^\S*python\S* -I scripts/(run_arm\.py (qwen35b|harness\S*)|refute\.py) ' >/dev/null; }
NOT_BEFORE="${NOT_BEFORE:-22:00}"   # overnight only (owner decision); HH:MM local time
SPLITS="${SPLITS:-dev_nc dev}"
log "waiting until ${NOT_BEFORE} and for stock-vLLM eval runs to finish"
target=$(date -d "today ${NOT_BEFORE}" +%s); now=$(date +%s)
[ "$now" -lt "$target" ] && sleep $((target - now))
sleep 120
while busy; do sleep 60; done
trap restore EXIT

log "stopping vllm-main"
sudo -n systemctl stop vllm-main
sleep 15
log "MemAvailable: $(awk '/MemAvailable/ {print int($2/1048576)" GiB"}' /proc/meminfo)"
# Same environment as vllm-main.service: vLLM JIT-compiles kernels and needs ninja on PATH.
systemd-run --user --unit vllm-abliterated --collect --working-directory=/srv/gateway \
  --setenv=CUTE_DSL_ARCH=sm_121a --setenv=MAX_JOBS=4 --setenv=VIRTUAL_ENV=/srv/gateway/vllm-env \
  --setenv=PATH=/srv/gateway/vllm-env/bin:/home/adamrel/.local/bin:/usr/local/cuda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  /srv/gateway/vllm-env/bin/vllm serve /srv/models/qwen3.6-35b-a3b-uncensored-nvfp4 \
  --served-model-name qwen3.6-35b-a3b-abliterated --trust-remote-code --gpu-memory-utilization 0.40 \
  --max-model-len 131072 --reasoning-parser qwen3 --no-enable-prefix-caching --gdn-prefill-backend triton \
  --no-async-scheduling --host 127.0.0.1 --port 8000
for i in $(seq 1 180); do   # first start JIT-compiles: allow 30 min
  if curl -sf localhost:8000/v1/models | grep -q abliterated; then break; fi
  systemctl --user is-active -q vllm-abliterated || { log "vllm-abliterated exited during startup"; exit 1; }
  sleep 10
done
curl -sf localhost:8000/v1/models | grep -q abliterated || { log "abliterated model failed to come up"; exit 1; }
for split in $SPLITS; do
  log "abliterated model up; running $split (frontier sample)"
  .venv/bin/python -I scripts/run_arm.py qwen35b_abl --split $split --sample frontier --workers 6 \
    > logs/qwen35b_abl-$split.log 2>&1 || log "arm exited non-zero on $split (resumable)"
done
log "runs finished"
