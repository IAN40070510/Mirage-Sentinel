"""Deploy commerce releases with a preview gate and revision-pinned images."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def ensure_capacity(root: Path) -> None:
    """Reclaim only regenerable, unused old build cache; never images or volumes."""
    minimum = 6 * 1024**3
    free = shutil.disk_usage(root).free
    print(f"Deployment filesystem free: {free / 1024**3:.2f} GiB", flush=True)
    if free < minimum:
        subprocess.run(
            ["docker", "builder", "prune", "--all", "--force", "--filter", "until=168h"],
            check=True,
        )
        free = shutil.disk_usage(root).free
        print(f"Free after old build-cache recovery: {free / 1024**3:.2f} GiB", flush=True)
    if free < minimum:
        raise SystemExit("Less than 6 GiB free after cache recovery; images and data retained")


def reuse_commerce_images(previous_tag: str, revision: str) -> list[str]:
    """Retag unchanged commerce builds while retaining all rollback image tags."""
    services = {"real-medusa": "mirage-commerce-medusa", "real-storefront": "mirage-commerce-storefront"}
    build = ["gateway", *services]
    if not re.fullmatch(r"[a-f0-9]{40}", previous_tag):
        return build
    trees = []
    for ref in (previous_tag, revision):
        result = subprocess.run(["git", "-c", f"safe.directory={ROOT}", "rev-parse", f"{ref}:commerce"], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        tree = result.stdout.strip()
        if result.returncode or not re.fullmatch(r"[a-f0-9]{40}", tree):
            return build
        trees.append(tree)
    dirty = subprocess.run(["git", "-c", f"safe.directory={ROOT}", "status", "--porcelain", "--untracked-files=all", "--", "commerce"],
                           cwd=ROOT, capture_output=True, text=True, check=True)
    if trees[0] != trees[1] or dirty.stdout.strip():
        return build
    for service, image in services.items():
        old = f"{image}:{previous_tag}"
        if subprocess.run(["docker", "image", "inspect", old], capture_output=True, check=False).returncode:
            continue
        subprocess.run(["docker", "tag", old, f"{image}:{revision}"], check=True)
        build.remove(service)
        print(f"Reusing unchanged {service} image; previous tag retained", flush=True)
    return build


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-env", required=True, type=Path)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        parser.error("Expected a full Git commit SHA")
    ensure_capacity(ROOT)
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
    previous_tag = fields.get("COMMERCE_IMAGE_TAG", "")
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

    try:
        build_services = reuse_commerce_images(previous_tag, args.revision)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/deploy_commerce.py"),
                "--env-file",
                str(shared),
                "--build",
                "--initialize",
                "--preview",
                *[argument for service in build_services for argument in ("--build-service", service)],
            ],
            cwd=ROOT,
            check=True,
        )
        command(ROOT, "run", "--rm", "--no-deps", "-v",
                f"{ROOT / 'scripts/wait_commerce.py'}:/tmp/check.py:ro",
                "gateway", "python", "/tmp/check.py", "--url", "http://edge-preview:8080")
        command(ROOT, "exec", "-T", "gateway", "python", "/models/runtime.py", "--self-test")
        command(ROOT, "exec", "-T", "gateway", "python", "-c",
                'import os,json,urllib.request; '
                'req=urllib.request.Request("http://localhost:8000/_control/status",'
                'headers={"x-control-token":os.environ["CONTROL_TOKEN"]}); '
                'state=json.load(urllib.request.urlopen(req,timeout=10)); '
                'assert state["model"]=="ready_five_class", state["model"]; '
                'assert state["model_mode"]=="enforce", state["model_mode"]; '
                'print("Five-class model ready in enforce mode")')
        for script in ["smoke_commerce.py"]:
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
        command(ROOT, "--profile", "preview", "stop", "edge-preview")
        previous.write_text(str(ROOT) + "\n")
        print(
            "OCI commerce deployment passed. SOC: port 3000 (authentication required); admin: SSH tunnel to 127.0.0.1:9100."
        )
    except BaseException:
        shared.write_text(original)
        if previous_release and previous_release.is_dir():
            # Restores application images; schema downgrades are deliberately not automated.
            command(previous_release, "up", "-d")
        raise


if __name__ == "__main__":
    main()
