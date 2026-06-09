# Mirage-Sentinel Kernel Module

This optional Linux Kernel Module is the Kernel Programming component for the sandbox isolation work. The production enforcement remains Linux cgroup v2 through Docker/runtime settings and `ops/create_cgroups.sh`; this module adds a small kernel-space audit surface via procfs.

## What It Does

- Creates `/proc/mirage_cgroup_audit`.
- Reports millisecond precision kernel time using `ktime_get_real_ts64`.
- Reports the process reading the procfs file.
- Reports the expected sandbox cgroup v2 policy:
  - cgroup path
  - `memory.max`
  - `pids.max`
  - `cpu.max`

## Build

Run on a Linux host with kernel headers installed:

```bash
cd ops/kernel
make
```

## Load

```bash
sudo insmod mirage_cgroup_audit.ko \
  sandbox_cgroup=/sys/fs/cgroup/msdss_sandbox \
  memory_limit_mb=256 \
  pids_limit=64 \
  cpu_percent=20
```

## Inspect

```bash
cat /proc/mirage_cgroup_audit
```

Example output:

```text
mirage_sentinel_kernel_audit=enabled
timestamp_ms=1780800000.123
reader_pid=4242
reader_comm=cat
reader_uid=1000
sandbox_cgroup=/sys/fs/cgroup/msdss_sandbox
expected_memory_max_bytes=268435456
expected_pids_max=64
expected_cpu_max=20000 100000
kernel_jiffies=1234567
```

## Unload

```bash
sudo rmmod mirage_cgroup_audit
```

## Scope

This is intentionally read-only. It does not grant the honeypot container extra privileges and does not read or modify `traffic_logs.db`. The module is for assignment-grade Kernel Programming evidence and host-side auditability; cgroup v2 remains the enforcement mechanism.
