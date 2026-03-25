"""PM3 connection management -- single owner of all subprocess calls.

This module is the ONLY place that calls subprocess.run for pm3 commands.
Tools call into ConnectionManager, never subprocess directly. Same pattern
as connection.py in ble-mcp and session.py in mitm-mcp.

Each tool invocation runs pm3 -p <port> -c "<command>" as a single-call
subprocess. No persistent pm3 process is kept alive.
"""

from __future__ import annotations

import glob
import json
import logging
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pm3_mcp.parsers import strip_ansi

log = logging.getLogger(__name__)


def _sanitize_name(name: str) -> str:
    """Strip everything except alphanumerics, hyphens, and underscores."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", name) or "unnamed"


def _find_pm3() -> str | None:
    """Locate the pm3 binary. Returns path or None."""
    found = shutil.which("pm3")
    if found:
        return found
    for candidate in ["/usr/local/bin/pm3", "/usr/bin/pm3", "/opt/proxmark3/pm3"]:
        if Path(candidate).is_file():
            return candidate
    return None


def _detect_port() -> str | None:
    """Scan /dev/ttyACM* and return the first port where pm3 responds."""
    pm3_bin = _find_pm3()
    if pm3_bin is None:
        return None
    ports = sorted(glob.glob("/dev/ttyACM*"))
    for port in ports:
        result = _run_raw(port, "hw status", timeout=10)
        if result["success"]:
            log.info("Detected PM3 on %s", port)
            return port
    return None


def _run_raw(port: str, command: str, timeout: int = 30) -> dict[str, Any]:
    """Run a single pm3 command via subprocess. Returns result dict."""
    pm3_bin = _find_pm3()
    if pm3_bin is None:
        return {"success": False, "output": "", "returncode": -1, "error": "pm3 not found"}

    cmd = [pm3_bin, "-p", port, "-c", command]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = strip_ansi(proc.stdout + proc.stderr)
        return {
            "success": proc.returncode == 0,
            "output": output,
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "returncode": -1, "error": "timeout"}


class ConnectionManager:
    """Manages PM3 sessions and engagement folders.

    All subprocess usage for pm3 commands is confined to this class.
    Tools never call subprocess directly.
    """

    def __init__(self, engagements_dir: Path) -> None:
        self._engagements_dir = engagements_dir
        self._sessions: dict[str, dict[str, Any]] = {}

    def connect(
        self,
        engagement_name: str,
        port: str | None = None,
    ) -> str | None:
        """Connect to a PM3 device, create engagement folder.

        If port is None, auto-detect by scanning /dev/ttyACM* and running
        hw status on each. Returns session_id or None on failure.
        """
        if _find_pm3() is None:
            log.error("pm3 binary not found")
            return None

        if port is None:
            port = _detect_port()
            if port is None:
                log.error("No PM3 device detected on any ttyACM port")
                return None

        # Validate PM3 is responding on the given port
        result = _run_raw(port, "hw status", timeout=10)
        if not result["success"]:
            log.error("PM3 not responding on %s", port)
            return None

        sanitized = _sanitize_name(engagement_name)
        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M")
        folder_name = f"{timestamp}_PM3_{sanitized}"
        engagement_path = self._engagements_dir / folder_name
        counter = 1
        while engagement_path.exists():
            folder_name = f"{timestamp}_PM3_{sanitized}-{counter}"
            engagement_path = self._engagements_dir / folder_name
            counter += 1

        (engagement_path / "logs").mkdir(parents=True, exist_ok=True)
        (engagement_path / "artifacts").mkdir(parents=True, exist_ok=True)

        session_id = str(uuid.uuid4())[:8]

        config = {
            "session_id": session_id,
            "name": sanitized,
            "port": port,
            "date": timestamp,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        config_path = engagement_path / "config.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")

        self._sessions[session_id] = {
            "port": port,
            "engagement_path": engagement_path,
        }
        log.info("Session %s on %s -> %s", session_id, port, engagement_path)
        return session_id

    def disconnect(self, session_id: str) -> None:
        """Remove session from tracking. Raises KeyError if not found."""
        self._sessions.pop(session_id)
        log.info("Disconnected session %s", session_id)

    def get(self, session_id: str) -> dict[str, Any] | None:
        """Get session info. Returns None if not found."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return {
            "port": session["port"],
            "engagement_path": str(session["engagement_path"]),
        }

    def run_command(
        self,
        session_id: str,
        command: str,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Run a pm3 command within a session.

        Raises KeyError if session_id not found.
        Returns dict with success, output, returncode (or error on timeout).
        """
        session = self._sessions[session_id]
        port = session["port"]
        result = _run_raw(port, command, timeout=timeout)
        self._log_command(session_id, command, result)
        return result

    def get_artifacts_path(self, session_id: str) -> Path | None:
        """Return path to the artifacts directory for a session."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return session["engagement_path"] / "artifacts"

    def _log_command(
        self,
        session_id: str,
        command: str,
        result: dict[str, Any],
    ) -> None:
        """Append command execution to the JSONL log."""
        session = self._sessions.get(session_id)
        if session is None:
            return
        log_path = session["engagement_path"] / "logs" / "pm3-commands.jsonl"
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "command": command,
            "success": result.get("success", False),
            "returncode": result.get("returncode"),
            "output_lines": len(result.get("output", "").splitlines()),
        }
        if "error" in result:
            entry["error"] = result["error"]
        with log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
