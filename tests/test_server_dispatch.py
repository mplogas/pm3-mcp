"""Dispatch tests for pm3-mcp.

Verifies that server.py call_tool correctly routes every tool name to the
corresponding tools.tool_* function without TypeError or missing arguments.
Tool functions are patched to AsyncMock so this tests ONLY the dispatch
routing and argument unpacking, not tool logic.
"""

import json

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from mcp.types import TextContent

from pm3_mcp import server, tools

TOOL_ARGS = {
    "connect": {"engagement_name": "test"},
    "disconnect": {"session_id": "t"},
    "hw_status": {"session_id": "t"},
    "detect_tag": {"session_id": "t"},
    "hf_info": {"session_id": "t"},
    "lf_info": {"session_id": "t"},
    "read_block": {"session_id": "t", "block_num": 0},
    "dump_tag": {"session_id": "t", "tag_type": "mf1k"},
    "autopwn": {"session_id": "t"},
    "darkside": {"session_id": "t"},
    "nested": {
        "session_id": "t",
        "known_key": "FFFFFFFFFFFF",
        "target_sector": 1,
    },
    "hardnested": {
        "session_id": "t",
        "known_key": "FFFFFFFFFFFF",
        "target_sector": 1,
    },
    "chk_keys": {"session_id": "t"},
    "desfire_info": {"session_id": "t"},
    "desfire_apps": {"session_id": "t"},
    "desfire_files": {"session_id": "t", "aid": "000357"},
    "iclass_info": {"session_id": "t"},
    "iclass_rdbl": {"session_id": "t", "block_num": 0},
    "iso15693_info": {"session_id": "t"},
    "iso15693_rdbl": {"session_id": "t", "block_num": 0},
    "iclass_dump": {"session_id": "t"},
    "iso15693_dump": {"session_id": "t"},
    "iclass_chk": {"session_id": "t"},
    "iclass_loclass": {"session_id": "t"},
    "mf_wrbl": {
        "session_id": "t",
        "block_num": 4,
        "key": "FFFFFFFFFFFF",
        "data": "00000000000000000000000000000000",
        "_confirmed": True,
    },
    "mf_restore": {
        "session_id": "t",
        "dump_file": "/tmp/dump.bin",
        "_confirmed": True,
    },
    "iclass_wrbl": {
        "session_id": "t",
        "block_num": 7,
        "key": "AFA785A7DAB33E",
        "data": "0000000000000000",
        "_confirmed": True,
    },
    "iso15693_wrbl": {
        "session_id": "t",
        "block_num": 0,
        "data": "DEADBEEF",
        "_confirmed": True,
    },
    "sniff_start": {"session_id": "t", "protocol": "14a"},
    "sniff_stop": {"session_id": "t", "protocol": "14a"},
}


@pytest.fixture(autouse=True)
def _mock_globals():
    """Patch module-level globals and all tool functions."""
    patches = [
        patch.object(server, "connection_manager", MagicMock()),
    ]
    for name in dir(tools):
        if name.startswith("tool_"):
            patches.append(
                patch.object(
                    tools, name, new_callable=AsyncMock, return_value={"ok": True}
                )
            )
    for p in patches:
        p.start()
    yield
    patch.stopall()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name,args", TOOL_ARGS.items())
async def test_dispatch(tool_name, args):
    """call_tool should route {tool_name} without crashing."""
    result = await server.call_tool(tool_name, args)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    data = json.loads(result[0].text)
    assert "Unknown tool" not in data.get("error", "")


async def test_unknown_tool():
    """Unknown tool names raise ValueError from classify_tool."""
    with pytest.raises(ValueError, match="Unknown tool"):
        await server.call_tool("nonexistent_tool", {})
