"""PM3 MCP server -- stdio transport.

Registers all tools from tools.py with the MCP SDK and runs the
server. Claude Code spawns this process and communicates over stdin/stdout.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from pm3_mcp.safety import classify_tool, SafetyTier
from pm3_mcp.connection import ConnectionManager
from pm3_mcp import tools

logger = logging.getLogger("pm3-mcp")

# Engagements dir: env var overrides, fallback to package root.
# In standalone mode: defaults to <repo>/engagements/
# When submoduled: parent repo sets PIDEV_ENGAGEMENTS_DIR via .mcp.json env.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENTS_DIR = Path(
    os.environ.get("PIDEV_ENGAGEMENTS_DIR", str(_PACKAGE_ROOT / "engagements"))
)

app = Server("pm3-mcp")
connection_manager = ConnectionManager(engagements_dir=ENGAGEMENTS_DIR)


TOOL_DEFINITIONS = [
    Tool(
        name="connect",
        description=(
            "Connect to a Proxmark3 device and create an engagement folder. "
            "Returns a session_id for subsequent calls. [allowed-write]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "port": {
                    "type": "string",
                    "description": "Serial port for the PM3 device (e.g. /dev/ttyACM0). "
                    "Omit to auto-detect.",
                },
                "engagement_name": {
                    "type": "string",
                    "description": "Target device or engagement name used for the folder",
                },
            },
            "required": ["engagement_name"],
        },
    ),
    Tool(
        name="disconnect",
        description="Disconnect a PM3 session by session ID. [allowed-write]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="hw_status",
        description=(
            "Run 'hw status' and return parsed PM3 device information. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="detect_tag",
        description=(
            "Run 'auto' to detect any nearby RFID/NFC tag. "
            "Returns raw PM3 output. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="hf_info",
        description=(
            "Run 'hf search' and, if a tag is found, 'hf 14a info'. "
            "Returns combined parsed result. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="lf_info",
        description=(
            "Run 'lf search' and return parsed low-frequency tag information. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="read_block",
        description=(
            "Read a single MIFARE Classic block by number. "
            "Returns hex and ASCII representations. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "block_num": {
                    "type": "integer",
                    "description": "Block number to read (0-based)",
                },
                "key": {
                    "type": "string",
                    "default": "FFFFFFFFFFFF",
                    "description": "Authentication key (12 hex chars, no spaces)",
                },
                "key_type": {
                    "type": "string",
                    "default": "A",
                    "description": "Key type: A or B",
                },
            },
            "required": ["session_id", "block_num"],
        },
    ),
    Tool(
        name="dump_tag",
        description=(
            "Dump a tag to the engagement artifacts directory. "
            "Supports MIFARE Classic 1K/4K and MIFARE Ultralight. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "tag_type": {
                    "type": "string",
                    "enum": ["mf1k", "mf4k", "mfu"],
                    "description": "Tag type: mf1k (MIFARE Classic 1K), "
                    "mf4k (MIFARE Classic 4K), mfu (MIFARE Ultralight)",
                },
                "key_file": {
                    "type": "string",
                    "description": "Path to a key dictionary file for MIFARE Classic dumps",
                },
            },
            "required": ["session_id", "tag_type"],
        },
    ),
    Tool(
        name="autopwn",
        description=(
            "Run 'hf mf autopwn' to automatically recover all MIFARE Classic keys. "
            "Chains dictionary, darkside, nested, and hardnested attacks as needed. "
            "Returns recovered keys and dump path. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="darkside",
        description=(
            "Run 'hf mf darkside' to recover a MIFARE Classic key using the "
            "darkside attack. Only works on cards with a weak PRNG. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="nested",
        description=(
            "Run 'hf mf nested' to recover unknown MIFARE Classic keys using a "
            "known key. Requires a working key for at least one sector. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "known_key": {
                    "type": "string",
                    "description": "Known authentication key (12 hex chars, no spaces)",
                },
                "known_key_type": {
                    "type": "string",
                    "default": "A",
                    "description": "Key type for the known key: A or B",
                },
                "target_sector": {
                    "type": "integer",
                    "description": "Sector number to attack",
                },
                "target_key_type": {
                    "type": "string",
                    "default": "A",
                    "description": "Key type to recover on the target sector: A or B",
                },
            },
            "required": ["session_id", "known_key", "target_sector"],
        },
    ),
    Tool(
        name="hardnested",
        description=(
            "Run 'hf mf hardnested' to recover unknown MIFARE Classic keys using a "
            "known key. Works on cards with a hard PRNG where nested fails. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "known_key": {
                    "type": "string",
                    "description": "Known authentication key (12 hex chars, no spaces)",
                },
                "known_key_type": {
                    "type": "string",
                    "default": "A",
                    "description": "Key type for the known key: A or B",
                },
                "target_sector": {
                    "type": "integer",
                    "description": "Sector number to attack",
                },
                "target_key_type": {
                    "type": "string",
                    "default": "A",
                    "description": "Key type to recover on the target sector: A or B",
                },
            },
            "required": ["session_id", "known_key", "target_sector"],
        },
    ),
    Tool(
        name="chk_keys",
        description=(
            "Run 'hf mf chk' to test a list of keys against all sectors. "
            "Returns which keys authenticate to which sectors. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "key_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of keys to test (12 hex chars each). "
                    "Omit to use the built-in PM3 default dictionary.",
                },
            },
            "required": ["session_id"],
        },
    ),
]


@app.list_tools()
async def list_tools():
    return TOOL_DEFINITIONS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    tier = classify_tool(name)
    logger.info("tool=%s tier=%s args=%s", name, tier.value, arguments)

    # No approval-write tools in MVP, but keep the gate for future use.
    if tier == SafetyTier.APPROVAL_WRITE:
        if not arguments.get("_confirmed", False):
            desc = f"{name}({', '.join(f'{k}={v}' for k, v in arguments.items())})"
            return [TextContent(
                type="text",
                text=json.dumps({
                    "confirmation_required": True,
                    "tool": name,
                    "arguments": arguments,
                    "message": f"APPROVAL REQUIRED: {desc}. "
                    f"Re-call with _confirmed=true to execute.",
                }),
            )]
        arguments = {k: v for k, v in arguments.items() if k != "_confirmed"}

    try:
        if name == "connect":
            result = await tools.tool_connect(
                manager=connection_manager,
                port=arguments.get("port"),
                engagement_name=arguments["engagement_name"],
            )

        elif name == "disconnect":
            result = await tools.tool_disconnect(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "hw_status":
            result = await tools.tool_hw_status(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "detect_tag":
            result = await tools.tool_detect_tag(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "hf_info":
            result = await tools.tool_hf_info(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "lf_info":
            result = await tools.tool_lf_info(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "read_block":
            result = await tools.tool_read_block(
                manager=connection_manager,
                session_id=arguments["session_id"],
                block_num=arguments["block_num"],
                key=arguments.get("key", "FFFFFFFFFFFF"),
                key_type=arguments.get("key_type", "A"),
            )

        elif name == "dump_tag":
            result = await tools.tool_dump_tag(
                manager=connection_manager,
                session_id=arguments["session_id"],
                tag_type=arguments["tag_type"],
                key_file=arguments.get("key_file"),
            )

        elif name == "autopwn":
            result = await tools.tool_autopwn(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "darkside":
            result = await tools.tool_darkside(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "nested":
            result = await tools.tool_nested(
                manager=connection_manager,
                session_id=arguments["session_id"],
                known_key=arguments["known_key"],
                known_key_type=arguments.get("known_key_type", "A"),
                target_sector=arguments["target_sector"],
                target_key_type=arguments.get("target_key_type", "A"),
            )

        elif name == "hardnested":
            result = await tools.tool_hardnested(
                manager=connection_manager,
                session_id=arguments["session_id"],
                known_key=arguments["known_key"],
                known_key_type=arguments.get("known_key_type", "A"),
                target_sector=arguments["target_sector"],
                target_key_type=arguments.get("target_key_type", "A"),
            )

        elif name == "chk_keys":
            result = await tools.tool_chk_keys(
                manager=connection_manager,
                session_id=arguments["session_id"],
                key_list=arguments.get("key_list"),
            )

        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as exc:
        logger.error("tool=%s error=%s", name, exc)
        result = {"error": str(exc), "tool": name}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
