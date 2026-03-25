"""Tool implementations for PM3 MCP server.

Each function takes a ConnectionManager and session_id (plus optional params),
runs the appropriate PM3 command, parses the output, and returns a dict.

All functions are async to match the MCP server's async context even though
connection.py uses subprocess (blocking). This keeps the interface uniform.

Error handling:
  - KeyError from manager.run_command/disconnect -> missing session -> {"error": ...}
  - Exception from PM3 subprocess layer -> {"error": ...}
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pm3_mcp import parsers
from pm3_mcp.connection import ConnectionManager

log = logging.getLogger(__name__)

_VALID_TAG_TYPES = {"mf1k", "mf4k", "mfu"}

_DUMP_COMMANDS = {
    "mf1k": "hf mf dump",
    "mf4k": "hf mf dump --4k",
    "mfu": "hf mfu dump",
}


async def tool_connect(
    manager: ConnectionManager,
    port: str | None,
    engagement_name: str,
) -> dict[str, Any]:
    """Connect to a PM3 device and create an engagement folder.

    Returns session_id, port, and engagement path on success.
    Returns {"error": ...} on failure.
    """
    try:
        session_id = manager.connect(engagement_name, port=port)
    except Exception as exc:
        log.error("connect failed: %s", exc)
        return {"error": str(exc)}

    if session_id is None:
        return {"error": "PM3 not found or not responding"}

    session = manager.get(session_id)
    return {
        "session_id": session_id,
        "port": session["port"],
        "engagement_path": session["engagement_path"],
    }


async def tool_disconnect(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Disconnect from a PM3 session.

    Returns {"disconnected": True} or {"error": ...}.
    """
    try:
        manager.disconnect(session_id)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("disconnect failed: %s", exc)
        return {"error": str(exc)}

    return {"disconnected": True}


async def tool_hw_status(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hw status' and return parsed device information.

    Returns parsed status dict or {"error": ...}.
    """
    try:
        result = manager.run_command(session_id, "hw status")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("hw status failed: %s", exc)
        return {"error": str(exc)}

    if not result.get("success"):
        err = result.get("error", "hw status command failed")
        return {"error": err}

    return parsers.parse_hw_status(result["output"])


async def tool_detect_tag(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'auto' to detect any nearby tag.

    Returns {"raw": output, "success": bool} or {"error": ...}.
    """
    try:
        result = manager.run_command(session_id, "auto", timeout=45)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("detect_tag failed: %s", exc)
        return {"error": str(exc)}

    return {
        "raw": result.get("output", ""),
        "success": result.get("success", False),
    }


async def tool_hf_info(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf search', and if a tag is found, run 'hf 14a info'.

    Returns combined parsed result or {"error": ...}.
    """
    try:
        search_result = manager.run_command(session_id, "hf search")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("hf_info search failed: %s", exc)
        return {"error": str(exc)}

    search_parsed = parsers.parse_hf_search(search_result.get("output", ""))

    if not search_parsed["found"]:
        return {
            "found": False,
            "search": search_parsed,
            "info": None,
        }

    try:
        info_result = manager.run_command(session_id, "hf 14a info")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("hf_info info failed: %s", exc)
        return {"error": str(exc)}

    info_parsed = parsers.parse_hf_14a_info(info_result.get("output", ""))

    return {
        "found": True,
        "search": search_parsed,
        "info": info_parsed,
    }


async def tool_lf_info(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'lf search' and return parsed result.

    Returns parsed lf search dict or {"error": ...}.
    """
    try:
        result = manager.run_command(session_id, "lf search")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("lf_info failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_lf_search(result.get("output", ""))


async def tool_read_block(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
    key: str = "FFFFFFFFFFFF",
    key_type: str = "A",
) -> dict[str, Any]:
    """Read a single MIFARE block.

    Runs 'hf mf rdbl --blk N -k KEY -a' (or -b for key type B).
    Returns parsed block data or {"error": ...}.
    """
    key_flag = "-a" if key_type.upper() == "A" else "-b"
    command = f"hf mf rdbl --blk {block_num} -k {key} {key_flag}"

    try:
        result = manager.run_command(session_id, command)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("read_block failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_block_read(result.get("output", ""))


async def tool_dump_tag(
    manager: ConnectionManager,
    session_id: str,
    tag_type: str,
    key_file: str | None = None,
) -> dict[str, Any]:
    """Dump a tag to the engagement artifacts directory.

    tag_type must be one of: mf1k, mf4k, mfu.
    Runs the appropriate dump command with timeout=120.
    Returns parsed dump result or {"error": ...}.
    """
    if tag_type not in _VALID_TAG_TYPES:
        return {
            "error": (
                f"unsupported tag type: {tag_type!r}. "
                f"Must be one of: {', '.join(sorted(_VALID_TAG_TYPES))}"
            )
        }

    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    dump_path = str(artifacts_path)
    base_command = _DUMP_COMMANDS[tag_type]

    command = base_command
    if key_file is not None:
        command = f"{command} -f {key_file}"

    try:
        result = manager.run_command(session_id, command, timeout=120)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("dump_tag failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_dump_result(result.get("output", ""), dump_path)
