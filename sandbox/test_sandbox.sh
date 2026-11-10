#!/usr/bin/env bash
# Safety tests for vs-sandbox: each must hold before any PoC runs.
set -u
B=/srv/gateway/vulnscan/sandbox/target/release/vs-sandbox
W=$(mktemp -d /tmp/vs-sbx-test.XXXX); S=$W/status.json; fail=0
PY=/usr/bin/python3
RO=(--ro /usr --ro /lib --ro /etc/ld.so.cache)
run() { "$B" --rw "$W" "${RO[@]}" --status "$S" "$@" > "$W/out" 2>&1; }
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; cat "$W/out" "$S"; fail=1; fi; }
run -- $PY -c 'print("hello")'; check "runs python" 'grep -q hello "$W/out"'
run -- $PY -c 'import socket; socket.socket(socket.AF_INET).connect(("1.1.1.1",53)); print("NET-OK")'
check "inet socket denied" '! grep -q NET-OK "$W/out"'
run -- $PY -c 'open("/tmp/vs-sbx-escape","w").write("x"); print("WROTE")'
check "write outside workspace denied" '! grep -q WROTE "$W/out" && [ ! -e /tmp/vs-sbx-escape ]'
run -- $PY -c 'open("inside.txt","w").write("x"); print("INSIDE-OK")'
check "write inside workspace allowed" 'grep -q INSIDE-OK "$W/out"'
run -- $PY -c 'print(open("/home/adamrel/.ssh/known_hosts").read()[:10])'
check "read outside ro paths denied" 'grep -q -i "permission\|denied\|error" "$W/out"'
"$B" --rw "$W" "${RO[@]}" --wall-s 2 --status "$S" -- $PY -c 'import time; time.sleep(30)' >/dev/null 2>&1
check "wall clock kill" 'grep -q "\"timed_out\":true" "$S"'
SCOPE=(systemd-run --user --scope --quiet -p TasksMax=32 -p MemoryMax=1G -p MemorySwapMax=0 -p OOMPolicy=continue)
"${SCOPE[@]}" "$B" --rw "$W" "${RO[@]}" --wall-s 10 --status "$S" -- $PY -c '
import os
n=0
try:
    while True:
        if os.fork()==0:
            import time; time.sleep(5); os._exit(0)
        n+=1
except OSError: print("CAPPED", n)' > "$W/out" 2>&1
check "process count capped" 'grep -q CAPPED "$W/out"'
"${SCOPE[@]}" "$B" --rw "$W" "${RO[@]}" --status "$S" -- $PY -c 'x = bytearray(2*1024**3); x[::4096] = b"x" * len(x[::4096]); print("ALLOC-OK")' > "$W/out" 2>&1
check "memory capped (cgroup, no swap; PoC killed, runner reports)" '! grep -q ALLOC-OK "$W/out" && grep -q "\"signal\":9" "$S"'
rm -rf "$W"; exit $fail
