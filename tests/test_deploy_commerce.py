"""Exercise release updates without connecting to Docker or OCI."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace, ModuleType
from typing import Any

import pytest


@pytest.fixture
def deployment_module() -> ModuleType:
    script = Path(__file__).resolve().parents[1] / "scripts/deploy_oci_commerce.py"
    spec = importlib.util.spec_from_file_location("storage_deploy_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("recovered", [True, False])
def test_low_space_only_reclaims_old_unused_cache(deployment_module: ModuleType, monkeypatch: pytest.MonkeyPatch, recovered: bool) -> None:
    free = iter([2 * 1024**3, (7 if recovered else 3) * 1024**3])
    monkeypatch.setattr(deployment_module.shutil, "disk_usage", lambda _: SimpleNamespace(free=next(free)))
    calls = []
    monkeypatch.setattr(deployment_module.subprocess, "run", lambda command, **kw: calls.append(command))
    if recovered:
        deployment_module.ensure_capacity(Path("."))
    else:
        with pytest.raises(SystemExit, match="images and data retained"):
            deployment_module.ensure_capacity(Path("."))
    assert calls == [["docker", "builder", "prune", "--all", "--force", "--filter", "until=168h"]]


@pytest.mark.parametrize("changed,dirty,missing", [(False,False,False), (True,False,False),
                                                  (False,True,False), (False,False,True)])
def test_reuse_requires_identical_clean_sources_and_existing_images(
    deployment_module: ModuleType, monkeypatch: pytest.MonkeyPatch, changed: bool, dirty: bool, missing: bool
) -> None:
    calls = []
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        output = ""
        code = 0
        if "rev-parse" in command:
            output = ("2" if changed and command[-1].startswith("b") else "1") * 40
        if "status" in command:
            output = " M commerce/package.json" if dirty else ""
        if command[:3] == ["docker", "image", "inspect"]:
            code = int(missing)
        return subprocess.CompletedProcess(command, code, stdout=output)
    monkeypatch.setattr(deployment_module.subprocess, "run", run)
    result = deployment_module.reuse_commerce_images("a" * 40, "b" * 40)
    if changed or dirty or missing:
        assert result == ["gateway", "real-medusa", "real-storefront"]
        assert not any(c[:2] == ["docker", "tag"] for c in calls)
    else:
        assert result == ["gateway"]
        assert sum(c[:2] == ["docker", "tag"] for c in calls) == 2
    assert not any("rm" in c or "prune" in c for c in calls)


@pytest.mark.parametrize("fail_preview", [False, True])
def test_commerce_release_and_failure_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_preview: bool
) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts/deploy_oci_commerce.py"
    spec = importlib.util.spec_from_file_location("commerce_deploy_test", script)
    assert spec is not None and spec.loader is not None
    deployment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deployment)
    current = tmp_path / "new-release"
    previous = tmp_path / "previous-release"
    current.mkdir()
    previous.mkdir()
    environment = tmp_path / ".env.commerce"
    original = "PUBLIC_URL=http://example.invalid\nSOC_PORT=3000\nCOMMERCE_IMAGE_TAG=previous\n"
    environment.write_text(original, encoding="utf-8")
    marker = tmp_path / "commerce-current-release"
    marker.write_text(str(previous), encoding="utf-8")
    monkeypatch.setattr(deployment, "ROOT", current)
    monkeypatch.setattr(
        deployment.shutil, "disk_usage", lambda _: SimpleNamespace(free=10 * 1024**3)
    )
    monkeypatch.setattr(
        sys, "argv",
        [str(script), "--shared-env", str(environment), "--public-url",
         "http://example.invalid", "--revision", "a" * 40],
    )
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(value) for value in command]
        calls.append(command)
        if fail_preview and "http://edge-preview:8080" in command:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(deployment.subprocess, "run", run)
    if fail_preview:
        with pytest.raises(subprocess.CalledProcessError):
            deployment.main()
        assert environment.read_text(encoding="utf-8") == original
        assert marker.read_text(encoding="utf-8").strip() == str(previous)
        assert any(str(previous / "docker-compose.commerce.yml") in call
                   and call[-2:] == ["up", "-d"] for call in calls)
    else:
        deployment.main()
        assert marker.read_text(encoding="utf-8").strip() == str(current)
        assert "COMMERCE_IMAGE_TAG=" + "a" * 40 in environment.read_text(encoding="utf-8")
        assert any(call[-4:] == ["up", "-d", "--no-deps", "edge"] for call in calls)

    # Neither success nor rollback may manage historical containers or delete data.
    assert all("mirage_sentinel" not in " ".join(call) for call in calls)
    assert all("down" not in call and "prune" not in call for call in calls)
