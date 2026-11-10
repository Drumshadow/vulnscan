#!/usr/bin/env bash
# U3 training window: stop Nemotron (approved), train the triage model, ALWAYS restart Nemotron.
# DeepHat is left running (its eval arm may be active); stop it too only if MemAvailable is short.
set -euo pipefail
cd /srv/gateway/vulnscan
log() { echo "[$(date -Is)] $*"; }
stopped=()
restore() {
  for s in "${stopped[@]}"; do
    log "restarting $s"; sudo -n systemctl start "$s" || true
    sleep 5; log "$s: $(systemctl is-active "$s")"
  done
}
trap restore EXIT
log "stopping llamacpp-second (Nemotron)"
sudo -n systemctl stop llamacpp-second; stopped+=(llamacpp-second)
sleep 10
avail=$(awk '/MemAvailable/ {print int($2/1048576)}' /proc/meminfo)
log "MemAvailable ${avail} GiB"
NEED_GB="${NEED_GB:-25}"
if [ "$avail" -lt "$NEED_GB" ]; then
  log "short on memory: stopping llamacpp-deephat too"
  sudo -n systemctl stop llamacpp-deephat; stopped+=(llamacpp-deephat); sleep 10
fi
export HF_HOME=$PWD/data/hf_home
# wait for any DeepHat eval run before stopping DeepHat
while ps -eo args | grep -E '^\S*python\S* -I scripts/run_arm\.py deephat ' >/dev/null; do sleep 60; done
.venv/bin/python -I "scripts/${TRAIN_SCRIPT:-train_triage.py}" --out "${OUT:-runs/triage-1.5b-v1}" "$@" || log "training exited non-zero"
log "training finished"
