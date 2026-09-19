"""Package source only; exclude secrets, dependencies, databases and build outputs."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {
    "node_modules",
    ".git",
    ".next",
    ".medusa",
    ".turbo",
    "__pycache__",
    ".pytest_cache",
}


def source_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for directory, folders, files in os.walk(root):
        folders[:] = [name for name in folders if name not in EXCLUDE]
        for name in files:
            yield Path(directory) / name


def main() -> None:
    output = ROOT / "artifacts" / "mirage-commerce-source.zip"
    output.parent.mkdir(exist_ok=True)
    includes = [
        "commerce",
        "services/commerce",
        "services/__init__.py",
        "deploy/commerce",
        "docker-compose.commerce.yml",
        "model/commerce",
        "tests/test_commerce.py",
        "scripts/prepare_commerce.py",
        "scripts/deploy_commerce.py",
        "scripts/deploy_oci_commerce.py",
        "scripts/wait_commerce.py",
        "scripts/smoke_commerce.py",
        "scripts/package_commerce.py",
        "docs/COMMERCE_MIGRATION_REPORT.md",
        "AGENTS.md",
        "LICENSE",
        ".gitignore",
        "artifacts/commerce-tests.xml",
        ".github/workflows/commerce-ci.yml",
        ".github/workflows/deploy.yml",
        ".github/workflows/post-deploy-smoke.yml",
    ]
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name in includes:
            source = ROOT / name
            paths = source_files(source)
            for path in paths:
                relative = path.relative_to(ROOT)
                if any(part in EXCLUDE for part in relative.parts):
                    continue
                if not path.is_file() or path.name.endswith(
                    (".tsbuildinfo", ".db", ".pyc")
                ):
                    continue
                if path.name.startswith(".env") and not path.name.endswith(".template"):
                    continue
                archive.write(path, relative.as_posix())
    print(
        f"Created {output} ({output.stat().st_size} bytes); no deployment secrets included"
    )


if __name__ == "__main__":
    main()
