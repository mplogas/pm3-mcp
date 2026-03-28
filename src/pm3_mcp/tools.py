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
import re
from pathlib import Path
from typing import Any

from pm3_mcp import parsers
from pm3_mcp.parsers import sector_to_trailer
from pm3_mcp.connection import ConnectionManager

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input validation -- prevent command injection via pm3 -c semicolons
# ---------------------------------------------------------------------------

# Characters that act as command separators or shell metacharacters in pm3 -c
_DANGEROUS_CHARS = re.compile(r'[;|><&`$]')


def _validate_hex(value: str, length: int, name: str) -> None:
    """Validate a hex string has exact length and contains only hex chars."""
    if not re.fullmatch(r'[0-9a-fA-F]+', value):
        raise ValueError(f"{name} must be hex-only, got: {value!r}")
    if len(value) != length:
        raise ValueError(f"{name} must be {length} hex chars, got {len(value)}")


def _validate_hex_data(value: str, name: str) -> None:
    """Validate hex data string (even length, hex chars only)."""
    if not re.fullmatch(r'[0-9a-fA-F]+', value):
        raise ValueError(f"{name} must be hex-only, got: {value!r}")
    if len(value) % 2 != 0:
        raise ValueError(f"{name} must be even length hex, got {len(value)}")


def _validate_block(block: int, max_block: int = 255) -> None:
    """Validate block number is in valid range."""
    if not isinstance(block, int) or block < 0 or block > max_block:
        raise ValueError(f"Block must be 0-{max_block}, got: {block}")


def _validate_sector(sector: int, max_sector: int = 39) -> None:
    """Validate sector number is in valid range."""
    if not isinstance(sector, int) or sector < 0 or sector > max_sector:
        raise ValueError(f"Sector must be 0-{max_sector}, got: {sector}")


def _validate_no_injection(value: str, name: str) -> None:
    """Reject any value containing command injection characters."""
    if _DANGEROUS_CHARS.search(value):
        raise ValueError(f"{name} contains dangerous characters: {value!r}")


def _validate_path(value: str, name: str) -> None:
    """Validate a file path has no injection characters."""
    _validate_no_injection(value, name)


def _validate_key_type(key_type: str) -> None:
    """Validate MIFARE key type is A or B."""
    if key_type.upper() not in ("A", "B"):
        raise ValueError(f"key_type must be A or B, got: {key_type!r}")


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
    project_path: str | None = None,
) -> dict[str, Any]:
    """Connect to a PM3 device and create an engagement folder.

    Returns session_id, port, and engagement path on success.
    Returns {"error": ...} on failure.
    """
    try:
        session_id = manager.connect(engagement_name, port=port, project_path=project_path)
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

    Returns structured detection result with protocol, UID, tag type,
    and suggested_tools for the agent to call next.
    """
    try:
        result = manager.run_command(session_id, "auto", timeout=45)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("detect_tag failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_detect_tag(result.get("output", ""))


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
    try:
        _validate_block(block_num)
        _validate_hex(key, 12, "key")
        _validate_key_type(key_type)
    except ValueError as exc:
        return {"error": str(exc)}

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

    if key_file is not None:
        try:
            _validate_path(key_file, "key_file")
        except ValueError as exc:
            return {"error": str(exc)}

    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    if key_file is not None:
        resolved = Path(key_file).resolve()
        eng_resolved = artifacts_path.parent.resolve()
        if not resolved.is_relative_to(eng_resolved):
            return {"error": f"Path must be under engagement directory: {key_file}"}

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


async def tool_autopwn(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf mf autopwn' and dump all sector keys to the engagement artifacts directory.

    Uses a 300-second timeout. Returns parsed autopwn result or {"error": ...}.
    """
    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    # autopwn generates hf-mf-<UID>-dump.bin/.json/-key.bin in the cwd.
    # -f is for dictionary input, not output path.
    command = "hf mf autopwn"

    try:
        result = manager.run_command(session_id, command, timeout=600)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("autopwn failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_autopwn(result.get("output", ""))


async def tool_darkside(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf mf darkside' to recover a key via the Darkside attack.

    Returns parsed darkside result or {"error": ...}.
    """
    try:
        result = manager.run_command(session_id, "hf mf darkside", timeout=60)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("darkside failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_darkside(result.get("output", ""))


async def tool_nested(
    manager: ConnectionManager,
    session_id: str,
    known_key: str,
    known_key_type: str,
    target_sector: int,
    target_key_type: str,
) -> dict[str, Any]:
    """Run 'hf mf nested' to recover a key via the Nested attack.

    Uses sector 0 as the known sector. known_key_type and target_key_type
    must be 'A' or 'B'.
    Returns parsed result or {"error": ...}.
    """
    try:
        _validate_hex(known_key, 12, "known_key")
        _validate_key_type(known_key_type)
        _validate_sector(target_sector)
        _validate_key_type(target_key_type)
    except ValueError as exc:
        return {"error": str(exc)}

    known_blk = sector_to_trailer(0)
    known_flag = "-a" if known_key_type.upper() == "A" else "-b"
    target_blk = sector_to_trailer(target_sector)
    target_flag = "--ta" if target_key_type.upper() == "A" else "--tb"

    command = (
        f"hf mf nested --blk {known_blk} {known_flag} -k {known_key} "
        f"--tblk {target_blk} {target_flag}"
    )

    try:
        result = manager.run_command(session_id, command, timeout=60)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("nested failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_hardnested(result.get("output", ""))


async def tool_hardnested(
    manager: ConnectionManager,
    session_id: str,
    known_key: str,
    known_key_type: str,
    target_sector: int,
    target_key_type: str,
) -> dict[str, Any]:
    """Run 'hf mf hardnested' to recover a key via the Hardnested attack.

    Uses sector 0 as the known sector. known_key_type and target_key_type
    must be 'A' or 'B'.
    Returns parsed result or {"error": ...}.
    """
    try:
        _validate_hex(known_key, 12, "known_key")
        _validate_key_type(known_key_type)
        _validate_sector(target_sector)
        _validate_key_type(target_key_type)
    except ValueError as exc:
        return {"error": str(exc)}

    known_blk = sector_to_trailer(0)
    known_flag = "-a" if known_key_type.upper() == "A" else "-b"
    target_blk = sector_to_trailer(target_sector)
    target_flag = "--ta" if target_key_type.upper() == "A" else "--tb"

    command = (
        f"hf mf hardnested --blk {known_blk} {known_flag} -k {known_key} "
        f"--tblk {target_blk} {target_flag}"
    )

    try:
        result = manager.run_command(session_id, command, timeout=120)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("hardnested failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_hardnested(result.get("output", ""))


async def tool_chk_keys(
    manager: ConnectionManager,
    session_id: str,
    key_list: list[str] | None = None,
) -> dict[str, Any]:
    """Run 'hf mf chk --1k' to check default and provided keys against all sectors.

    If key_list is provided, appends '-k KEY' for each entry.
    Returns parsed chk result or {"error": ...}.
    """
    if key_list:
        try:
            for key in key_list:
                _validate_hex(key, 12, "key")
        except ValueError as exc:
            return {"error": str(exc)}

    command = "hf mf chk --1k"
    if key_list:
        for key in key_list:
            command += f" -k {key}"

    try:
        result = manager.run_command(session_id, command, timeout=60)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("chk_keys failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_chk_keys(result.get("output", ""))


async def tool_desfire_info(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf mfdes info' to get DESFire tag details.

    Returns UID, version, storage, applications, auth methods.
    """
    try:
        result = manager.run_command(session_id, "hf mfdes info", timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("desfire_info failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_desfire_info(result.get("output", ""))


async def tool_desfire_apps(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf mfdes lsapp --no-auth' to enumerate DESFire applications.

    Returns application IDs, descriptions, and auth requirements.
    """
    try:
        result = manager.run_command(session_id, "hf mfdes lsapp --no-auth", timeout=30)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("desfire_apps failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_desfire_apps(result.get("output", ""))


async def tool_desfire_files(
    manager: ConnectionManager,
    session_id: str,
    aid: str,
) -> dict[str, Any]:
    """Run 'hf mfdes lsfiles --no-auth --aid <AID>' to list files in a DESFire application.

    Most applications require authentication, so this will typically return
    an auth-required error. That itself is a finding (properly secured).
    """
    try:
        _validate_hex(aid, 6, "aid")
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        result = manager.run_command(
            session_id, f"hf mfdes lsfiles --no-auth --aid {aid}", timeout=15,
        )
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("desfire_files failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_desfire_files(result.get("output", ""))


# ---------------------------------------------------------------------------
# iCLASS / PicoPass
# ---------------------------------------------------------------------------

async def tool_iclass_info(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf iclass info' to get iCLASS tag details."""
    try:
        result = manager.run_command(session_id, "hf iclass info", timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_info failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iclass_info(result.get("output", ""))


async def tool_iclass_rdbl(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
    key: str | None = None,
    credit: bool = False,
) -> dict[str, Any]:
    """Read an iCLASS block.

    key: 8-byte hex key. If None, tries without auth (blocks 0-4 are usually readable).
    credit: use credit key instead of debit key.
    """
    try:
        _validate_block(block_num)
        if key:
            _validate_hex(key, 16, "key")
    except ValueError as exc:
        return {"error": str(exc)}

    command = f"hf iclass rdbl --blk {block_num}"
    if key:
        command += f" -k {key}"
        if credit:
            command += " --credit"

    try:
        result = manager.run_command(session_id, command, timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_rdbl failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iclass_rdbl(result.get("output", ""))


# ---------------------------------------------------------------------------
# ISO 15693
# ---------------------------------------------------------------------------

async def tool_iso15693_info(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Run 'hf 15 info' to get ISO 15693 tag details."""
    try:
        result = manager.run_command(session_id, "hf 15 info", timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iso15693_info failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iso15693_info(result.get("output", ""))


async def tool_iso15693_rdbl(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
) -> dict[str, Any]:
    """Read an ISO 15693 block."""
    try:
        _validate_block(block_num)
    except ValueError as exc:
        return {"error": str(exc)}

    command = f"hf 15 rdbl -b {block_num} -*"

    try:
        result = manager.run_command(session_id, command, timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iso15693_rdbl failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iso15693_rdbl(result.get("output", ""))


# ---------------------------------------------------------------------------
# Dumps (iCLASS, ISO 15693)
# ---------------------------------------------------------------------------

async def tool_iclass_dump(
    manager: ConnectionManager,
    session_id: str,
    key: str | None = None,
    credit_key: str | None = None,
) -> dict[str, Any]:
    """Dump iCLASS tag memory to file.

    key: 8-byte debit key hex. If None, tries without auth.
    credit_key: 8-byte credit key hex for credit-protected areas.
    """
    try:
        if key:
            _validate_hex(key, 16, "key")
        if credit_key:
            _validate_hex(credit_key, 16, "credit_key")
    except ValueError as exc:
        return {"error": str(exc)}

    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    dump_path = str(artifacts_path / "iclass-dump")
    command = f"hf iclass dump -f {dump_path}"
    if key:
        command += f" -k {key}"
    if credit_key:
        command += f" --credit {credit_key}"

    try:
        result = manager.run_command(session_id, command, timeout=60)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_dump failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_dump_result(result.get("output", ""), dump_path)


async def tool_iso15693_dump(
    manager: ConnectionManager,
    session_id: str,
) -> dict[str, Any]:
    """Dump ISO 15693 tag memory to file."""
    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    dump_path = str(artifacts_path / "iso15693-dump")
    command = f"hf 15 dump -f {dump_path} -*"

    try:
        result = manager.run_command(session_id, command, timeout=30)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iso15693_dump failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_dump_result(result.get("output", ""), dump_path)


# ---------------------------------------------------------------------------
# iCLASS key recovery
# ---------------------------------------------------------------------------

async def tool_iclass_chk(
    manager: ConnectionManager,
    session_id: str,
    credit: bool = False,
    elite: bool = False,
) -> dict[str, Any]:
    """Run 'hf iclass chk' to check keys from the built-in dictionary.

    credit: check as credit key instead of debit.
    elite: apply elite key diversification.
    """
    command = "hf iclass chk"
    if credit:
        command += " --credit"
    if elite:
        command += " --elite"

    try:
        result = manager.run_command(session_id, command, timeout=120)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_chk failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iclass_chk(result.get("output", ""))


async def tool_iclass_loclass(
    manager: ConnectionManager,
    session_id: str,
    trace_file: str | None = None,
) -> dict[str, Any]:
    """Run 'hf iclass loclass' to recover iCLASS keys via loclass attack.

    Requires a trace file from 'hf iclass sim -t 2' (sniffed NR/MAC pairs).
    If trace_file is None, uses the default location.
    """
    if trace_file:
        try:
            _validate_path(trace_file, "trace_file")
        except ValueError as exc:
            return {"error": str(exc)}

        artifacts_path = manager.get_artifacts_path(session_id)
        if artifacts_path is None:
            return {"error": f"session not found: {session_id}"}
        resolved = Path(trace_file).resolve()
        eng_resolved = artifacts_path.parent.resolve()
        if not resolved.is_relative_to(eng_resolved):
            return {"error": f"Path must be under engagement directory: {trace_file}"}

    command = "hf iclass loclass"
    if trace_file:
        command += f" -f {trace_file}"

    try:
        result = manager.run_command(session_id, command, timeout=300)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_loclass failed: %s", exc)
        return {"error": str(exc)}

    return parsers.parse_iclass_loclass(result.get("output", ""))


# ---------------------------------------------------------------------------
# Write operations (approval-write tier)
# ---------------------------------------------------------------------------

async def tool_mf_wrbl(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
    key: str,
    key_type: str,
    data: str,
) -> dict[str, Any]:
    """Write a MIFARE Classic block. DESTRUCTIVE: overwrites tag data.

    data: 16 bytes as 32 hex chars (no spaces).
    """
    try:
        _validate_block(block_num)
        _validate_hex(key, 12, "key")
        _validate_key_type(key_type)
        _validate_hex(data, 32, "data")
    except ValueError as exc:
        return {"error": str(exc)}

    key_flag = "-a" if key_type.upper() == "A" else "-b"
    command = f"hf mf wrbl --blk {block_num} -k {key} {key_flag} -d {data}"

    try:
        result = manager.run_command(session_id, command, timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("mf_wrbl failed: %s", exc)
        return {"error": str(exc)}

    output = result.get("output", "")
    success = ("isok" in output.lower() or "write" in output.lower()) and "error" not in output.lower()
    return {
        "success": success,
        "block": block_num,
        "error": None if success else output.strip(),
    }


async def tool_mf_restore(
    manager: ConnectionManager,
    session_id: str,
    dump_file: str,
    key_file: str | None = None,
    tag_size: str = "1k",
) -> dict[str, Any]:
    """Restore a full dump to a MIFARE Classic tag. DESTRUCTIVE: overwrites entire tag.

    dump_file: path to the .bin dump file.
    tag_size: "1k" or "4k".
    """
    try:
        _validate_path(dump_file, "dump_file")
        if key_file:
            _validate_path(key_file, "key_file")
        if tag_size not in ("1k", "4k"):
            raise ValueError(f"tag_size must be 1k or 4k, got: {tag_size!r}")
    except ValueError as exc:
        return {"error": str(exc)}

    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}
    eng_resolved = artifacts_path.parent.resolve()

    resolved_dump = Path(dump_file).resolve()
    if not resolved_dump.is_relative_to(eng_resolved):
        return {"error": f"Path must be under engagement directory: {dump_file}"}

    if key_file:
        resolved_key = Path(key_file).resolve()
        if not resolved_key.is_relative_to(eng_resolved):
            return {"error": f"Path must be under engagement directory: {key_file}"}

    size_flag = "--1k" if tag_size == "1k" else "--4k"
    command = f"hf mf restore {size_flag} -f {dump_file}"
    if key_file:
        command += f" -k {key_file} --ka"

    try:
        result = manager.run_command(session_id, command, timeout=120)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("mf_restore failed: %s", exc)
        return {"error": str(exc)}

    output = result.get("output", "")
    success = "done" in output.lower() or "restore" in output.lower()
    return {
        "success": success,
        "error": None if success else output.strip(),
    }


async def tool_iclass_wrbl(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
    key: str,
    data: str,
    credit: bool = False,
) -> dict[str, Any]:
    """Write an iCLASS block. DESTRUCTIVE: overwrites tag data.

    data: 8 bytes as 16 hex chars.
    """
    try:
        _validate_block(block_num)
        _validate_hex(key, 16, "key")
        _validate_hex(data, 16, "data")
    except ValueError as exc:
        return {"error": str(exc)}

    command = f"hf iclass wrbl --blk {block_num} -k {key} -d {data}"
    if credit:
        command += " --credit"

    try:
        result = manager.run_command(session_id, command, timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iclass_wrbl failed: %s", exc)
        return {"error": str(exc)}

    output = result.get("output", "")
    success = ("ok" in output.lower() or "write" in output.lower()) and "error" not in output.lower()
    return {
        "success": success,
        "block": block_num,
        "error": None if success else output.strip(),
    }


async def tool_iso15693_wrbl(
    manager: ConnectionManager,
    session_id: str,
    block_num: int,
    data: str,
) -> dict[str, Any]:
    """Write an ISO 15693 block. DESTRUCTIVE: overwrites tag data.

    data: 4 bytes as 8 hex chars.
    """
    try:
        _validate_block(block_num)
        _validate_hex(data, 8, "data")
    except ValueError as exc:
        return {"error": str(exc)}

    command = f"hf 15 wrbl -b {block_num} -d {data} -*"

    try:
        result = manager.run_command(session_id, command, timeout=15)
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("iso15693_wrbl failed: %s", exc)
        return {"error": str(exc)}

    output = result.get("output", "")
    success = ("ok" in output.lower() or "write" in output.lower()) and "error" not in output.lower()
    return {
        "success": success,
        "block": block_num,
        "error": None if success else output.strip(),
    }


# ---------------------------------------------------------------------------
# Sniff tools (read-only tier)
# ---------------------------------------------------------------------------

_VALID_SNIFF_PROTOCOLS = {"14a", "iclass", "15693"}

_SNIFF_COMMANDS = {
    "14a": "hf 14a sniff",
    "iclass": "hf iclass sniff",
    "15693": "hf 15 sniff",
}

_TRACE_LIST_FLAGS = {
    "14a": "14a",
    "iclass": "iclass",
    "15693": "15",
}


async def tool_sniff_start(
    manager: ConnectionManager,
    session_id: str,
    protocol: str,
) -> dict[str, Any]:
    """Start sniffing RF traffic for the given protocol.

    protocol must be one of: 14a, iclass, 15693.
    Blocks until the PM3 button is pressed to stop the sniff.
    Returns {success, protocol, output} or {"error": ...}.
    """
    if protocol not in _VALID_SNIFF_PROTOCOLS:
        return {
            "error": (
                f"unsupported protocol: {protocol!r}. "
                f"Must be one of: {', '.join(sorted(_VALID_SNIFF_PROTOCOLS))}"
            )
        }

    command = _SNIFF_COMMANDS[protocol]

    try:
        result = manager.run_sniff(session_id, command)
    except KeyError:
        return {"error": f"session not found: {session_id}"}

    return {
        "success": result.get("success", False),
        "protocol": protocol,
        "output": result.get("output", ""),
    }


async def tool_sniff_stop(
    manager: ConnectionManager,
    session_id: str,
    protocol: str,
) -> dict[str, Any]:
    """Decode and save the trace buffer after a sniff.

    protocol must be one of: 14a, iclass, 15693.
    Checks hw status for trace data, saves to artifacts, decodes with trace list.
    Returns {captured, trace_bytes, trace_file, exchanges, exchange_count, auth_nonces}
    or {captured: False, message: ...} if no data was captured.
    """
    if protocol not in _VALID_SNIFF_PROTOCOLS:
        return {
            "error": (
                f"unsupported protocol: {protocol!r}. "
                f"Must be one of: {', '.join(sorted(_VALID_SNIFF_PROTOCOLS))}"
            )
        }

    # Step 1: check trace length via hw status
    try:
        status_result = manager.run_command(session_id, "hw status")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("sniff_stop hw status failed: %s", exc)
        return {"error": str(exc)}

    trace_status = parsers.parse_hw_trace_status(status_result.get("output", ""))
    if trace_status["trace_len"] == 0:
        return {
            "captured": False,
            "message": "No data captured. Ensure a tag was present during the sniff.",
        }

    # Step 2: save the trace to artifacts
    artifacts_path = manager.get_artifacts_path(session_id)
    if artifacts_path is None:
        return {"error": f"session not found: {session_id}"}

    trace_file = str(artifacts_path / f"trace-{protocol}")

    try:
        _validate_path(trace_file, "trace_file")
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        manager.run_command(session_id, f"trace save -f {trace_file}")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("sniff_stop trace save failed: %s", exc)
        return {"error": str(exc)}

    # Step 3: load the trace
    try:
        manager.run_command(session_id, f"trace load -f {trace_file}")
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("sniff_stop trace load failed: %s", exc)
        return {"error": str(exc)}

    # Step 4: decode the trace with protocol-specific flag
    proto_flag = _TRACE_LIST_FLAGS[protocol]
    try:
        list_result = manager.run_command(
            session_id, f"trace list -t {proto_flag}"
        )
    except KeyError:
        return {"error": f"session not found: {session_id}"}
    except Exception as exc:
        log.error("sniff_stop trace list failed: %s", exc)
        return {"error": str(exc)}

    parsed = parsers.parse_trace_list(list_result.get("output", ""))

    return {
        "captured": True,
        "trace_bytes": parsed["trace_bytes"],
        "trace_file": trace_file,
        "exchanges": parsed["exchanges"],
        "exchange_count": parsed["exchange_count"],
        "auth_nonces": parsed["auth_nonces"],
    }
