"""Bounded HTTP readiness gate used by local, CI and OCI deployments."""

from __future__ import annotations

import argparse
import http.cookiejar
import time
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    while time.monotonic() < deadline:
        try:
            with opener.open(
                args.url.rstrip("/") + "/healthz", timeout=10
            ) as response:
                if response.status == 200:
                    with opener.open(
                        args.url.rstrip("/") + "/store/regions", timeout=10
                    ) as regions:
                        if regions.status == 200:
                            print("Commerce gateway and API ready")
                            return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(3)
    raise SystemExit("Commerce readiness deadline exceeded")


if __name__ == "__main__":
    main()
