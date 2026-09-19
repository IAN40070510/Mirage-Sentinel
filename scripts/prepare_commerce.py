"""Generate isolated deployment credentials; never overwrite an existing environment."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".env.commerce")
    parser.add_argument("--public-url", default="http://localhost:8080")
    args = parser.parse_args()
    from urllib.parse import urlsplit

    url = urlsplit(args.public_url)
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or any(c in args.public_url for c in "\r\n$# ")
    ):
        parser.error("Use a valid HTTP(S) origin")
    fields = {
        "PUBLIC_URL": args.public_url,
        "PUBLIC_SCHEME": url.scheme,
        "BIND_ADDRESS": "127.0.0.1",
        "HTTP_PORT": "8080",
        "SOC_PORT": "3100",
        "ADMIN_PORT": "9100",
        "SOC_USER": "analyst",
        "ADMIN_EMAIL": "admin@example.invalid",
        "OLLAMA_MODEL": "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:latest",
        "REAL_PUBLISHABLE_KEY": "",
        "SANDBOX_PUBLISHABLE_KEY": "",
    }
    for name in [
        "EDGE_TOKEN",
        "VISITOR_SIGNING_KEY",
        "AUDIT_WRITE_TOKEN",
        "CONTROL_TOKEN",
        "REAL_STOREFRONT_TOKEN",
        "SANDBOX_STOREFRONT_TOKEN",
        "SOC_PASSWORD",
        "ADMIN_PASSWORD",
        "REAL_DB_PASSWORD",
        "SANDBOX_DB_PASSWORD",
        "REAL_JWT_SECRET",
        "SANDBOX_JWT_SECRET",
        "REAL_COOKIE_SECRET",
        "SANDBOX_COOKIE_SECRET",
    ]:
        fields[name] = secrets.token_hex(32)
    path = Path(args.output)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
        output.write("# Local secrets: do not commit or paste into chat.\n")
        output.write("\n".join(f"{k}={v}" for k, v in fields.items()) + "\n")
    print(f"Created {path}. Values were not printed. Keep this file private.")


if __name__ == "__main__":
    main()
