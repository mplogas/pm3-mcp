"""Tests for PM3 connection management.

Mocks subprocess.run, shutil.which, and glob.glob -- no hardware needed.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pm3_mcp.connection import ConnectionManager, _detect_port, _find_pm3, _sanitize_name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_completed_process(stdout="", stderr="", returncode=0):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _hw_status_success():
    return _make_completed_process(stdout="[#] Memory\n[#] mode... fpga\n")


def _hw_status_failure():
    return _make_completed_process(stdout="", stderr="error", returncode=1)


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    """Session creation and engagement folder setup."""

    @patch("pm3_mcp.connection.glob.glob", return_value=["/dev/ttyACM0"])
    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_success())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_connect_creates_session(self, _which, _run, _glob, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test-device", port="/dev/ttyACM0")

        assert sid is not None
        session = mgr.get(sid)
        assert session is not None
        assert session["port"] == "/dev/ttyACM0"

    @patch("pm3_mcp.connection.glob.glob", return_value=["/dev/ttyACM0"])
    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_success())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_connect_creates_engagement_folder(self, _which, _run, _glob, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test-device", port="/dev/ttyACM0")

        session = mgr.get(sid)
        eng_path = Path(session["engagement_path"])
        assert eng_path.exists()
        assert (eng_path / "logs").is_dir()
        assert (eng_path / "artifacts").is_dir()
        assert (eng_path / "config.json").is_file()

    @patch("pm3_mcp.connection.glob.glob", return_value=["/dev/ttyACM0"])
    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_success())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_folder_name_follows_convention(self, _which, _run, _glob, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("my-tag", port="/dev/ttyACM0")

        session = mgr.get(sid)
        folder = Path(session["engagement_path"]).name
        # DD-MM-YYYY-HH-MM_PM3_<name>
        assert "_PM3_my-tag" in folder
        # Starts with date pattern
        parts = folder.split("_PM3_")
        assert len(parts) == 2
        date_part = parts[0]
        # Should have 5 hyphen-separated numeric groups
        assert len(date_part.split("-")) == 5

    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_success())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_name_sanitized(self, _which, _run, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("bad name!@#$%", port="/dev/ttyACM0")

        session = mgr.get(sid)
        folder = Path(session["engagement_path"]).name
        assert "_PM3_badname" in folder

    @patch("pm3_mcp.connection.Path.is_file", return_value=False)
    @patch("pm3_mcp.connection.shutil.which", return_value=None)
    def test_pm3_not_on_path_returns_none(self, _which, _is_file, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")
        assert sid is None

    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_failure())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_pm3_not_responding_returns_none(self, _which, _run, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")
        assert sid is None


# ---------------------------------------------------------------------------
# TestDisconnect
# ---------------------------------------------------------------------------

class TestDisconnect:
    """Session removal."""

    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_success())
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_disconnect_removes_session(self, _which, _run, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")
        assert sid is not None

        mgr.disconnect(sid)
        assert mgr.get(sid) is None

    def test_disconnect_nonexistent_raises_keyerror(self, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        with pytest.raises(KeyError):
            mgr.disconnect("nonexistent")


# ---------------------------------------------------------------------------
# TestRunCommand
# ---------------------------------------------------------------------------

class TestRunCommand:
    """Command execution and logging."""

    @patch("pm3_mcp.connection.subprocess.run")
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_run_command_correct_args(self, _which, mock_run, engagements_dir):
        # First call: hw status validation; second call: the actual command
        mock_run.side_effect = [
            _hw_status_success(),
            _make_completed_process(stdout="[+] Done\n"),
        ]
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")

        result = mgr.run_command(sid, "hf search")
        assert result["success"] is True
        assert "Done" in result["output"]

        # Verify the second call used correct args
        call_args = mock_run.call_args_list[1]
        cmd = call_args[0][0]
        assert cmd == ["/usr/bin/pm3", "-p", "/dev/ttyACM0", "-c", "hf search"]

    @patch("pm3_mcp.connection.subprocess.run")
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_run_command_logs_to_jsonl(self, _which, mock_run, engagements_dir):
        mock_run.side_effect = [
            _hw_status_success(),
            _make_completed_process(stdout="[+] Result\n"),
        ]
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")

        mgr.run_command(sid, "hw status")

        session = mgr.get(sid)
        log_path = Path(session["engagement_path"]) / "logs" / "pm3-commands.jsonl"
        assert log_path.exists()

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["command"] == "hw status"
        assert entry["success"] is True
        assert "timestamp" in entry

    @patch("pm3_mcp.connection.subprocess.run")
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_run_command_timeout_returns_error(self, _which, mock_run, engagements_dir):
        mock_run.side_effect = [
            _hw_status_success(),
            subprocess.TimeoutExpired(cmd="pm3", timeout=30),
        ]
        mgr = ConnectionManager(engagements_dir)
        sid = mgr.connect("test", port="/dev/ttyACM0")

        result = mgr.run_command(sid, "hf mf dump")
        assert result["success"] is False
        assert result["error"] == "timeout"

    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_run_command_nonexistent_session_raises_keyerror(self, _which, engagements_dir):
        mgr = ConnectionManager(engagements_dir)
        with pytest.raises(KeyError):
            mgr.run_command("nonexistent", "hw status")


# ---------------------------------------------------------------------------
# TestPortDetection
# ---------------------------------------------------------------------------

class TestPortDetection:
    """Auto-detection of PM3 port."""

    @patch("pm3_mcp.connection.subprocess.run")
    @patch("pm3_mcp.connection.glob.glob", return_value=["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2"])
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_detect_finds_pm3_on_acm2(self, _which, _glob, mock_run):
        """ACM0 and ACM1 fail, ACM2 succeeds."""
        mock_run.side_effect = [
            _hw_status_failure(),
            _hw_status_failure(),
            _hw_status_success(),
        ]
        port = _detect_port()
        assert port == "/dev/ttyACM2"

    @patch("pm3_mcp.connection.subprocess.run", return_value=_hw_status_failure())
    @patch("pm3_mcp.connection.glob.glob", return_value=["/dev/ttyACM0", "/dev/ttyACM1"])
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/bin/pm3")
    def test_detect_no_pm3_returns_none(self, _which, _glob, _run):
        port = _detect_port()
        assert port is None

    @patch("pm3_mcp.connection.Path.is_file", return_value=False)
    @patch("pm3_mcp.connection.shutil.which", return_value=None)
    def test_detect_no_binary_returns_none(self, _which, _is_file):
        port = _detect_port()
        assert port is None


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

class TestSanitizeName:
    def test_strips_special_chars(self):
        assert _sanitize_name("hello world!@#") == "helloworld"

    def test_preserves_hyphens_underscores(self):
        assert _sanitize_name("my-tag_v2") == "my-tag_v2"

    def test_empty_returns_unnamed(self):
        assert _sanitize_name("!!!") == "unnamed"


class TestFindPm3:
    @patch("pm3_mcp.connection.shutil.which", return_value="/usr/local/bin/pm3")
    def test_finds_via_which(self, _which):
        assert _find_pm3() == "/usr/local/bin/pm3"

    @patch("pm3_mcp.connection.Path.is_file", return_value=True)
    @patch("pm3_mcp.connection.shutil.which", return_value=None)
    def test_finds_via_fallback(self, _which, _is_file):
        result = _find_pm3()
        assert result is not None

    @patch("pm3_mcp.connection.Path.is_file", return_value=False)
    @patch("pm3_mcp.connection.shutil.which", return_value=None)
    def test_not_found(self, _which, _is_file):
        assert _find_pm3() is None
