"""OCI cutover with a preview gate, revision-pinned images and retained legacy data."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-env", required=True, type=Path)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        parser.error("Expected a full Git commit SHA")
    if shutil.disk_usage(ROOT).free < 6 * 1024**3:
        raise SystemExit(
            "Less than 6 GiB free; deployment stopped without pruning existing data"
        )
    shared = args.shared_env.resolve()
    if not shared.exists():
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/prepare_commerce.py"),
                "--output",
                str(shared),
                "--public-url",
                args.public_url,
            ],
            check=True,
        )
    original = shared.read_text(encoding="utf-8")
    fields = dict(
        line.split("=", 1)
        for line in original.splitlines()
        if "=" in line and not line.startswith("#")
    )
    if fields["PUBLIC_URL"] != args.public_url:
        raise SystemExit(
            "Existing PUBLIC_URL differs; update the private environment deliberately"
        )
    previous = shared.with_name("commerce-current-release")
    previous_release = Path(previous.read_text().strip()) if previous.exists() else None
    fields.update(
        BIND_ADDRESS="0.0.0.0",
        HTTP_PORT="80",
        SOC_PORT="3000",
        COMMERCE_IMAGE_TAG=args.revision,
    )
    # Do not show secrets in workflow logs or command-line arguments.
    shared.write_text(
        "\n".join(f"{key}={value}" for key, value in fields.items()) + "\n"
    )
    shared.chmod(0o600)
    compose = ["docker", "compose"]
    if subprocess.run(
        compose + ["version"], capture_output=True, check=False
    ).returncode:
        compose = ["docker-compose"]

    def command(
        release: Path, *arguments: str, capture: bool = False
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            compose
            + [
                "--env-file",
                str(shared),
                "-f",
                str(release / "docker-compose.commerce.yml"),
                *arguments,
            ],
            cwd=release,
            check=True,
            text=True,
            capture_output=capture,
        )

    stopped_legacy = False
    try:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/deploy_commerce.py"),
                "--env-file",
                str(shared),
                "--build",
                "--initialize",
                "--preview",
            ],
            cwd=ROOT,
            check=True,
        )
        for script in ["wait_commerce.py", "smoke_commerce.py"]:
            command(
                ROOT,
                "run",
                "--rm",
                "--no-deps",
                "-v",
                f"{ROOT / 'scripts' / script}:/tmp/check.py:ro",
                "gateway",
                "python",
                "/tmp/check.py",
                "--url",
                "http://edge-preview:8080",
            )
        legacy = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Running}}",
                "mirage_sentinel_nginx",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if legacy.returncode == 0 and legacy.stdout.strip() == "true":
            subprocess.run(["docker", "stop", "mirage_sentinel_nginx"], check=True)
            stopped_legacy = True
        command(ROOT, "up", "-d", "--no-deps", "edge")
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/wait_commerce.py"),
                "--url",
                "http://127.0.0.1",
            ],
            check=True,
        )
        # Old SOC serves bank-only data. Retain it stopped rather than exposing a stale room.
        old_soc = subprocess.run(
            ["docker", "inspect", "mirage_sentinel_frontend_soc"],
            capture_output=True,
            check=False,
        )
        if old_soc.returncode == 0:
            subprocess.run(
                ["docker", "stop", "mirage_sentinel_frontend_soc"], check=True
            )
        command(ROOT, "--profile", "preview", "stop", "edge-preview")
        previous.write_text(str(ROOT) + "\n")
        print(
            "OCI commerce cutover passed. SOC: SSH tunnel to 127.0.0.1:3100; admin: 9100."
        )
    except BaseException:
        shared.write_text(original)
        if previous_release and previous_release.is_dir():
            # Restores application images; schema downgrades are deliberately not automated.
            command(previous_release, "up", "-d")
        elif stopped_legacy:
            subprocess.run(
                compose
                + [
                    "--env-file",
                    str(shared),
                    "-f",
                    str(ROOT / "docker-compose.commerce.yml"),
                    "stop",
                    "edge",
                ],
                cwd=ROOT,
                check=False,
            )
            subprocess.run(["docker", "start", "mirage_sentinel_nginx"], check=True)
        raise


if __name__ == "__main__":
    main()
