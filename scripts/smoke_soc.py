"""Verify public SOC viewing and protected mutations without reading events."""
from __future__ import annotations

import argparse
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:3000")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    for path in ("/", "/api/status"):
        with urllib.request.urlopen(base + path, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"SOC {path}: HTTP {response.status}")
    request = urllib.request.Request(
        base + "/api/release/" + "0" * 32,
        method="POST", headers={"x-soc-action": "release"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            raise RuntimeError("Anonymous SOC release must be rejected")
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
    print("PASS: SOC opens without login; anonymous release is denied")


if __name__ == "__main__":
    main()
