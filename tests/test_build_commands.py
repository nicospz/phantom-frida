import os
import subprocess
import sys
from pathlib import Path

import pytest

import build


def test_cli_exposes_strict_wx_as_an_explicit_opt_in() -> None:
    result = subprocess.run(
        [sys.executable, str(Path(build.__file__)), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "--strict-wx" in result.stdout
    assert "--strict-wx-agent-only" in result.stdout
    assert "Frida-owned persistent anonymous RWX" in result.stdout


def test_cli_exposes_injector_diagnostics_as_an_explicit_opt_in() -> None:
    result = subprocess.run(
        [sys.executable, str(Path(build.__file__)), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "--injector-diagnostics" in result.stdout
    assert "failed ptrace writes" in result.stdout


def test_run_passes_argument_vector_without_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    build.run(["tool", "value with spaces"], cwd=tmp_path)

    assert captured["command"] == ["tool", "value with spaces"]
    assert captured.get("shell", False) is False
    assert captured["cwd"] == tmp_path


def test_run_merges_environment_and_supports_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = build.run(["tool"], env={"PHANTOM_TEST": "enabled"}, capture_output=True)

    child_env = captured["env"]
    assert isinstance(child_env, dict)
    assert child_env["PHANTOM_TEST"] == "enabled"
    assert child_env.get("PATH") == os.environ.get("PATH")
    assert captured["capture_output"] is True
    assert result.stdout == "ok\n"


def test_run_raises_build_error_for_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="exit code 7"):
        build.run(["tool", "arg"])


def test_validate_gadget_socket_accepts_abstract_name() -> None:
    assert (
        build.validate_gadget_socket("pgexplorations-gadget-22220")
        == "pgexplorations-gadget-22220"
    )


@pytest.mark.parametrize("value", ["", "unix:name", "name/with/slash", "x" * 91])
def test_validate_gadget_socket_rejects_unsafe_name(value: str) -> None:
    with pytest.raises(build.BuildError, match="Gadget socket"):
        build.validate_gadget_socket(value)


def test_validate_gadget_script_accepts_relative_asset_path() -> None:
    assert (
        build.validate_gadget_script("../agent/auto-farmer.js")
        == "../agent/auto-farmer.js"
    )


@pytest.mark.parametrize(
    "value", ["", "/absolute/agent.js", "agent script.js", "agent\\script.js", "./agent.js"]
)
def test_validate_gadget_script_rejects_unsafe_path(value: str) -> None:
    with pytest.raises(build.BuildError, match="Gadget script"):
        build.validate_gadget_script(value)


def test_embedded_gadget_config_avoids_external_file_read(tmp_path: Path) -> None:
    target = tmp_path / "subprojects/frida-core/lib/gadget/gadget.vala"
    target.parent.mkdir(parents=True)
    target.write_text(
        "\tprivate Config load_config (Location location) throws Error {\n"
        "\t\tunowned string? gadget_path = location.path;\n",
        encoding="utf-8",
    )

    build.apply_embedded_gadget_config_patch(
        tmp_path, socket_name="pgexplorations-gadget-22220"
    )

    result = target.read_text(encoding="utf-8")
    assert 'address\\\":\\\"unix:pgexplorations-gadget-22220' in result
    assert 'on_load\\\":\\\"resume' in result
    assert result.index("return parse_config") < result.index("gadget_path")


def test_embedded_gadget_script_uses_relative_asset_path(tmp_path: Path) -> None:
    target = tmp_path / "subprojects/frida-core/lib/gadget/gadget.vala"
    target.parent.mkdir(parents=True)
    target.write_text(
        "\tprivate Config load_config (Location location) throws Error {\n"
        "\t\tunowned string? gadget_path = location.path;\n",
        encoding="utf-8",
    )

    build.apply_embedded_gadget_config_patch(
        tmp_path, script_path="../agent/auto-farmer.js"
    )

    result = target.read_text(encoding="utf-8")
    assert 'type\\\":\\\"script' in result
    assert 'path\\\":\\\"../agent/auto-farmer.js' in result
    assert 'on_change\\\":\\\"ignore' in result
