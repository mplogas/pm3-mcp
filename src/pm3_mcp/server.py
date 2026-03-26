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
    Tool(
        name="desfire_info",
        description=(
            "Run 'hf mfdes info' on a DESFire tag. Returns UID, version, "
            "storage, applications, auth methods, signature verification. [read-only]"
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
        name="desfire_apps",
        description=(
            "Enumerate DESFire applications without authentication. "
            "Returns AIDs, descriptions, and auth requirements per app. [read-only]"
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
        name="desfire_files",
        description=(
            "List files in a DESFire application (typically requires auth). "
            "An auth-required error is itself a finding: properly secured. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by connect",
                },
                "aid": {
                    "type": "string",
                    "description": "Application ID (hex, e.g. 000357)",
                },
            },
            "required": ["session_id", "aid"],
        },
    ),
    Tool(
        name="iclass_info",
        description="Get iCLASS / PicoPass tag information (CSN, card type). [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="iclass_rdbl",
        description="Read an iCLASS / PicoPass block. Blocks 0-4 are usually readable without a key. [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
                "block_num": {"type": "integer", "description": "Block number to read"},
                "key": {"type": "string", "description": "8-byte hex key (omit for unauthenticated read)"},
                "credit": {"type": "boolean", "default": False, "description": "Use credit key instead of debit key"},
            },
            "required": ["session_id", "block_num"],
        },
    ),
    Tool(
        name="iso15693_info",
        description="Get ISO 15693 tag information (UID, type, manufacturer). [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="iso15693_rdbl",
        description="Read an ISO 15693 block. [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
                "block_num": {"type": "integer", "description": "Block number to read"},
            },
            "required": ["session_id", "block_num"],
        },
    ),
    Tool(
        name="iclass_dump",
        description="Dump iCLASS / PicoPass tag memory to file. [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
                "key": {"type": "string", "description": "8-byte debit key hex (omit for unauthenticated)"},
                "credit_key": {"type": "string", "description": "8-byte credit key hex"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="iso15693_dump",
        description="Dump ISO 15693 tag memory to file. [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="iclass_chk",
        description="Check iCLASS keys from built-in dictionary. [read-only]",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
                "credit": {"type": "boolean", "default": False, "description": "Check as credit key"},
                "elite": {"type": "boolean", "default": False, "description": "Apply elite key diversification"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="iclass_loclass",
        description=(
            "Recover iCLASS key via loclass attack. Requires a trace file "
            "from 'hf iclass sim -t 2'. [read-only]"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID returned by connect"},
                "trace_file": {"type": "string", "description": "Path to NR/MAC trace file (omit for default)"},
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

        elif name == "desfire_info":
            result = await tools.tool_desfire_info(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "desfire_apps":
            result = await tools.tool_desfire_apps(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "desfire_files":
            result = await tools.tool_desfire_files(
                manager=connection_manager,
                session_id=arguments["session_id"],
                aid=arguments["aid"],
            )

        elif name == "iclass_info":
            result = await tools.tool_iclass_info(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "iclass_rdbl":
            result = await tools.tool_iclass_rdbl(
                manager=connection_manager,
                session_id=arguments["session_id"],
                block_num=arguments["block_num"],
                key=arguments.get("key"),
                credit=arguments.get("credit", False),
            )

        elif name == "iso15693_info":
            result = await tools.tool_iso15693_info(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "iso15693_rdbl":
            result = await tools.tool_iso15693_rdbl(
                manager=connection_manager,
                session_id=arguments["session_id"],
                block_num=arguments["block_num"],
            )

        elif name == "iclass_dump":
            result = await tools.tool_iclass_dump(
                manager=connection_manager,
                session_id=arguments["session_id"],
                key=arguments.get("key"),
                credit_key=arguments.get("credit_key"),
            )

        elif name == "iso15693_dump":
            result = await tools.tool_iso15693_dump(
                manager=connection_manager,
                session_id=arguments["session_id"],
            )

        elif name == "iclass_chk":
            result = await tools.tool_iclass_chk(
                manager=connection_manager,
                session_id=arguments["session_id"],
                credit=arguments.get("credit", False),
                elite=arguments.get("elite", False),
            )

        elif name == "iclass_loclass":
            result = await tools.tool_iclass_loclass(
                manager=connection_manager,
                session_id=arguments["session_id"],
                trace_file=arguments.get("trace_file"),
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
