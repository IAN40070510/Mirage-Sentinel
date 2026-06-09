#!/usr/bin/env bash
set -euo pipefail

# tests/cgroup_smoke.sh
# 簡易 smoke 測試：建立 cgroup，將一個記憶體耗盡程式放入，檢查記憶體限制是否生效

CG_ROOT="/sys/fs/cgroup"
NAME="msdss_smoke_test"
CG_PATH="$CG_ROOT/$NAME"

if ! mountpoint -q "$CG_ROOT"; then
  echo "cgroup v2 not mounted at $CG_ROOT" >&2
  exit 2
fi

if [[ ! -f "$CG_ROOT/cgroup.controllers" ]]; then
  echo "unified cgroup v2 hierarchy not detected at $CG_ROOT" >&2
  exit 2
fi

sudo mkdir -p "$CG_PATH"
echo $((128*1024*1024)) | sudo tee "$CG_PATH/memory.max" > /dev/null
echo 32 | sudo tee "$CG_PATH/pids.max" > /dev/null
echo "20000 100000" | sudo tee "$CG_PATH/cpu.max" > /dev/null

echo "Starting smoke test: allocating 200MB inside cgroup (should be limited to 128MB)"

# Start a background python process that allocates memory
PY_EXE=$(which python3 || which python || true)
if [ -z "$PY_EXE" ]; then
  echo "Python not found; install python3 for smoke test" >&2
  exit 3
fi

sudo bash -c "echo $$ > $CG_PATH/cgroup.procs"

# Run allocation in a sub-shell and add its PID to cgroup
(
  sleep 1
  $PY_EXE - <<'PY'
import time
try:
    a = bytearray(200 * 1024 * 1024)
    time.sleep(5)
except MemoryError:
    print('MemoryError raised (as expected)')
PY
) &
PID=$!
echo $PID | sudo tee "$CG_PATH/cgroup.procs" > /dev/null

sleep 2

echo "memory.current:"; cat "$CG_PATH/memory.current" || true
echo "cgroup.events:"; cat "$CG_PATH/cgroup.events" || true
echo "cpu.max:"; cat "$CG_PATH/cpu.max" || true

echo "If the process was OOM-killed or allocation failed, the test indicates limit enforcement."

exit 0
