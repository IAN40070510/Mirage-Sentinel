#!/usr/bin/env bash
set -euo pipefail

# ops/create_cgroups.sh
# 建立並初始化 cgroup v2 範例群組

CG_ROOT="/sys/fs/cgroup"
CG_NAME="msdss_sandbox"
CG_PATH="$CG_ROOT/$CG_NAME"

usage(){
  cat <<EOF
Usage: $0 [--name NAME] [--memory MB] [--pids N] [--cpu-percent P]
Example: $0 --name msdss_sandbox --memory 256 --pids 64 --cpu-percent 20
EOF
  exit 1
}

NAME="${CG_NAME}"
MEM_MB=256
PIDS=64
CPU_PERCENT=20

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --memory) MEM_MB="$2"; shift 2;;
    --pids) PIDS="$2"; shift 2;;
    --cpu-percent) CPU_PERCENT="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

CG_PATH="$CG_ROOT/$NAME"

if ! mountpoint -q "$CG_ROOT"; then
  echo "Error: $CG_ROOT is not a mountpoint. Is cgroup v2 enabled?" >&2
  exit 2
fi

if [[ ! -f "$CG_ROOT/cgroup.controllers" ]]; then
  echo "Error: unified cgroup v2 hierarchy was not detected at $CG_ROOT." >&2
  exit 2
fi

sudo mkdir -p "$CG_PATH"

# memory.max expects bytes
MEM_BYTES=$((MEM_MB * 1024 * 1024))
echo "$MEM_BYTES" | sudo tee "$CG_PATH/memory.max" > /dev/null
echo "$PIDS" | sudo tee "$CG_PATH/pids.max" > /dev/null

# cpu.max: quota period. To set percentage, use quota = percent * period / 100
PERIOD=100000
QUOTA=$((CPU_PERCENT * PERIOD / 100))
echo "$QUOTA $PERIOD" | sudo tee "$CG_PATH/cpu.max" > /dev/null

echo "Created cgroup at $CG_PATH with memory=${MEM_MB}M pids=${PIDS} cpu%=${CPU_PERCENT}"

echo "To add a process to this cgroup, run:"
echo "  echo <PID> | sudo tee $CG_PATH/cgroup.procs"

exit 0
