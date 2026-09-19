"""Build and initialize a separate Compose project. Never stops the existing bank."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default=".env.commerce")
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="Migrate two NEW commerce databases and export their public keys",
    )
    parser.add_argument("--build", action="store_true")
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Start loopback preview before public cutover",
    )
    args = parser.parse_args()
    environment = (ROOT / args.env_file).resolve()
    if not environment.is_file():
        parser.error("Run prepare_commerce.py first")
    compose = ["docker", "compose"]
    if subprocess.run(
        compose + ["version"], capture_output=True, check=False
    ).returncode:
        compose = ["docker-compose"]
    compose += [
        "--env-file",
        str(environment),
        "-f",
        str(ROOT / "docker-compose.commerce.yml"),
    ]

    def run(arguments: list[str], capture: bool = False) -> str:
        result = subprocess.run(
            compose + arguments,
            cwd=ROOT,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=capture,
        )
        return result.stdout if capture else ""

    run(["config", "--quiet"])
    if args.build:
        # Sequential builds are intentional for the four-core A1 host.
        for service in ["gateway", "real-medusa", "real-storefront"]:
            run(["build", service])
    if args.initialize:
        run(["up", "-d", "real-db", "sandbox-db"])
        keys: dict[str, str] = {}
        for realm in ["real", "sandbox"]:
            service = realm + "-medusa"
            run(
                [
                    "run",
                    "--rm",
                    service,
                    "node",
                    "../../node_modules/@medusajs/cli/cli.js",
                    "db:migrate",
                ]
            )
            # The migration script is tracked by Medusa and runs only once.
            output = run(
                [
                    "run",
                    "--rm",
                    service,
                    "node",
                    "../../node_modules/@medusajs/cli/cli.js",
                    "exec",
                    "./src/scripts/export-store-key.js",
                ],
                capture=True,
            )
            found = re.search(r"STORE_KEY=(pk_[A-Za-z0-9_]+)", output)
            if not found:
                raise RuntimeError(f"{realm}: seeded publishable key not found")
            keys[realm.upper() + "_PUBLISHABLE_KEY"] = found.group(1)
        lines = environment.read_text(encoding="utf-8").splitlines()
        environment.write_text(
            "\n".join(
                f"{line.split('=', 1)[0]}={keys[line.split('=', 1)[0]]}"
                if line.split("=", 1)[0] in keys
                else line
                for line in lines
            )
            + "\n",
            encoding="utf-8",
        )
        # Pass only the two admin variables, not the entire deployment secret file.
        values = dict(
            line.split("=", 1)
            for line in lines
            if "=" in line and not line.startswith("#")
        )
        admin_env = {
            **os.environ,
            "ADMIN_EMAIL": values["ADMIN_EMAIL"],
            "ADMIN_PASSWORD": values["ADMIN_PASSWORD"],
        }
        subprocess.run(
            compose
            + [
                "run",
                "--rm",
                "-e",
                "ADMIN_EMAIL",
                "-e",
                "ADMIN_PASSWORD",
                "real-medusa",
                "node",
                "../../node_modules/@medusajs/cli/cli.js",
                "exec",
                "./src/scripts/create-demo-admin.js",
            ],
            cwd=ROOT,
            env=admin_env,
            check=True,
        )
    if args.preview:
        run(
            [
                "--profile",
                "preview",
                "up",
                "-d",
                "gateway",
                "collector",
                "real-storefront",
                "sandbox-storefront",
                "real-medusa",
                "sandbox-medusa",
                "mirage",
                "edge-preview",
            ]
        )
    else:
        run(["up", "-d"])
    print(
        "Commerce stack started. Existing Mirage-Sentinel containers were not changed."
    )
    print(
        "Run scripts/smoke_commerce.py against the configured loopback endpoint before public cutover."
    )


if __name__ == "__main__":
    main()
