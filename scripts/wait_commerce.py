"""Bounded HTTP readiness gate used by local, CI and OCI deployments."""

from __future__ import annotations

import argparse
import time
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                args.url.rstrip("/") + "/healthz", timeout=10
            ) as response:
                if response.status == 200:
                    print("Commerce gateway ready")
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(3)
    raise SystemExit("Commerce readiness deadline exceeded")


if __name__ == "__main__":
    main()
