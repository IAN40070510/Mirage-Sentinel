"""Bounded HTTP readiness gate used by local, CI and OCI deployments."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
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
    last_issue = "No successful full-stack response"
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
                            data = json.load(regions)
                            country = data['regions'][0]['countries'][0]['iso_2']
                            if not isinstance(country, str) or not re.fullmatch(r'[a-z]{2}', country):
                                raise ValueError('Invalid storefront country')
                            with opener.open(args.url.rstrip('/') + '/' + country, timeout=10) as home:
                                if home.status == 200:
                                    print("Commerce gateway, API and storefront ready")
                                    return
                                last_issue = f'Storefront HTTP {home.status}'
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError) as exc:
            last_issue = str(exc)
        time.sleep(3)
    raise SystemExit("Commerce readiness deadline exceeded: " + last_issue)


if __name__ == "__main__":
    main()
