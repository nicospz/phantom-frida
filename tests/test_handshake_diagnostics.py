import shutil
import subprocess
from pathlib import Path

import pytest

import build

FIXTURES = Path("tests/fixtures/frida-17.16.4")


def source_tree(root: Path) -> Path:
    linux = root / "subprojects/frida-core/src/linux"
    helpers = linux / "helpers"
    helpers.mkdir(parents=True)
    for name in ("loader.c", "inject-context.h", "syscall.h"):
        shutil.copyfile(FIXTURES / f"handshake-{name}", helpers / name)
    shutil.copyfile(FIXTURES / "handshake-monitor.vala", linux / "oemcodec-helper-backend.vala")
    # The full backend also contains an unrelated cancellation handler with this prefix.
    monitor = linux / "oemcodec-helper-backend.vala"
    monitor.write_text(monitor.read_text() +
                       "\n\t\t\t} catch (GLib.Error e) {\n"
                       "\t\t\t\tif (!(e is IOError.CANCELLED))\n"
                       "\t\t\t\t\tthrow e;\n")
    return helpers


def test_contract_rejects_loader_drift(tmp_path: Path) -> None:
    helpers = source_tree(tmp_path)
    loader = helpers / "loader.c"
    loader.write_text(
        loader.read_text().replace("agent_codefd = frida_receive_fd", "agent_codefd = changed")
    )
    with pytest.raises(build.BuildError, match="source contract drift"):
        build.apply_injector_handshake_diagnostics_patch(tmp_path, "oemcodec")


def test_native_loader_checkpoints_preserve_success_failure_and_dropped_diagnostics(
    tmp_path: Path,
) -> None:
    helpers = source_tree(tmp_path)
    build.apply_injector_handshake_diagnostics_patch(tmp_path, "oemcodec")
    harness = helpers / "harness.c"
    harness.write_text((FIXTURES / "handshake-harness.c").read_text())
    binary = helpers / "test-loader"
    subprocess.run(
        ["cc", "-std=gnu11", "-Wall", "-Werror", str(harness), "-o", str(binary)], check=True
    )
    for scenario in range(5):
        subprocess.run([str(binary), str(scenario)], check=True, timeout=5)
    monitor = (helpers.parent / "oemcodec-helper-backend.vala").read_text()
    assert "event=handshake-incomplete" in monitor
    assert "event=handshake-io-error" in monitor
    assert "e.message" not in monitor.split("event=handshake-io-error", 1)[1].split("if (!(e", 1)[0]


def test_diagnostic_wire_values_match_without_changing_existing_messages(tmp_path: Path) -> None:
    helpers = source_tree(tmp_path)
    build.apply_injector_handshake_diagnostics_patch(tmp_path, "oemcodec")
    header = (helpers / "inject-context.h").read_text()
    monitor = (helpers.parent / "oemcodec-helper-backend.vala").read_text()
    c_values = header.split("enum _FridaMessageType", 1)[1].split("};", 1)[0]
    vala_values = monitor.split("enum HelperMessageType", 1)[1].split("}", 1)[0]
    import re

    c_names = re.findall(r"FRIDA_MESSAGE_(\w+)", c_values)
    vala_names = re.findall(r"\b([A-Z][A-Z_]+)\b", vala_values)
    assert c_names == vala_names
    assert c_names[:6] == ["HELLO", "READY", "ACK", "BYE", "ERROR_DLOPEN", "ERROR_DLSYM"]
    assert len(c_names) == 19
