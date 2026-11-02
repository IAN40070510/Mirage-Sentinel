"""Verify public SOC viewing and public release validation without reading events."""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import time
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:3000")
    parser.add_argument("--commerce-url")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    for path in ("/", "/api/status"):
        with urllib.request.urlopen(base + path, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"SOC {path}: HTTP {response.status}")
    request = urllib.request.Request(
        base + "/api/release/invalid-visitor",
        method="POST", headers={"x-soc-action": "release"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            raise RuntimeError("Invalid visitor must be rejected")
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise
    if args.commerce_url:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        with opener.open(args.commerce_url.rstrip("/") + "/store/regions", timeout=15) as response:
            if response.status != 200:
                raise RuntimeError("Commerce request failed")
        visitor = next(cookie.value.split(".")[0] for cookie in jar if cookie.name == "visitor_id")
        deadline = time.monotonic() + 15
        while True:
            with urllib.request.urlopen(base + "/api/events?latest=true&visitor=" + visitor, timeout=10) as response:
                events = json.load(response)
            if any(event.get("path") == "/store/regions" and event.get("status") == 200 for event in events):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Own commerce request did not appear in SOC")
            time.sleep(0.5)
        print("PASS: new commerce request is visible in SOC")
    print("PASS: SOC opens without login; release requires no login and rejects invalid visitors")


if __name__ == "__main__":
    main()
