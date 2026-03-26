# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project

pm3-mcp is an MCP server that wraps the Proxmark3 iceman client for RFID/NFC
tag identification and reading, exposing operations as MCP tools over stdio
transport.

## Architecture

    MCP client (Claude Code, etc.)
      |
      stdio transport
      |
    pm3-mcp (server.py)
      |
      tools.py -> connection.py -> subprocess.run("pm3 -p PORT -c CMD")
      |
    Proxmark3 (iceman fw) via USB serial

connection.py is the ONLY module that calls subprocess. Everything else talks
to connection.py. Each tool call runs a single pm3 command (no persistent
process).

parsers.py contains output parsing logic, separated from tool logic. Each PM3
command has its own parser function.

## Safety Model

Three tiers enforced at the MCP server boundary:

- **read-only**: full autonomy (hw_status, detect_tag, hf_info, lf_info, read_block, dump_tag, autopwn, darkside, nested, hardnested, chk_keys, desfire_info, desfire_apps, desfire_files)
- **allowed-write**: autonomous but logged (connect, disconnect)
- **approval-write**: reserved for future write/clone operations (no MVP tools)

## Build and Run

    # Install (use project venv)
    pip install -e ".[dev]"

    # Tests (no PM3 hardware needed)
    pytest

    # Integration tests (PM3 required)
    pytest tests/ -m proxmark3

## Prerequisites

- Proxmark3 with iceman firmware (pm3 client on PATH)
- User in dialout group for serial access

## Style

- Python 3.11+
- No emojis, no em-dashes in code, comments, commits, or docs
- Commit messages: short, to the point
