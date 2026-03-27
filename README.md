# pm3-mcp

MCP server for Proxmark3 RFID/NFC tag identification and reading. Wraps the [iceman firmware](https://github.com/RfidResearchGroup/proxmark3) client to detect, identify, and dump tag contents via single subprocess calls. Exposes operations as [Model Context Protocol](https://modelcontextprotocol.io/) tools over stdio transport.

Built for use with Claude Code on a Raspberry Pi 5, but works with any MCP client on any system with a Proxmark3.

## What it does

- **Tag detection:** auto-detect LF and HF tags (MIFARE, EM410x, HID, iClass, DESFire, etc.)
- **HF identification:** UID, ATQA, SAK, protocol details, PRNG weakness detection, magic tag identification
- **LF identification:** tag type, ID, modulation
- **Block reading:** read individual MIFARE Classic blocks with key authentication
- **Memory dumping:** full tag dumps (MIFARE Classic 1K/4K, Ultralight) saved as artifacts
- **Engagement logging:** timestamped command log (JSONL), per-engagement folders

## Requirements

- Python 3.11+
- Proxmark3 with iceman firmware (`pm3` client on PATH)
- User in `dialout` group for serial access (`sudo usermod -aG dialout $USER`)
- Build iceman from source: https://github.com/RfidResearchGroup/proxmark3

## Install

```bash
git clone https://github.com/mplogas/pm3-mcp.git
cd pm3-mcp
pip install -e ".[dev]"
```

## MCP Client Configuration

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "pm3": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "pm3_mcp"],
      "env": {
        "PIDEV_ENGAGEMENTS_DIR": "/path/to/engagements"
      }
    }
  }
}
```

Set `PIDEV_ENGAGEMENTS_DIR` to control where engagement logs are written. Defaults to `./engagements/` relative to the package root.

## Tools

| Tool | Safety Tier | Description |
|---|---|---|
| `hw_status` | read-only | Device info, firmware, key dictionaries loaded |
| `detect_tag` | read-only | Auto-detect any LF/HF tag on the reader |
| `hf_info` | read-only | Detailed HF tag identification (ISO14443A) |
| `lf_info` | read-only | LF tag protocol identification |
| `read_block` | read-only | Read a single MIFARE Classic block |
| `dump_tag` | read-only | Full memory dump (MIFARE Classic 1K/4K, Ultralight) |
| `autopwn` | read-only | Auto-recover all MIFARE Classic keys (dictionary + darkside + nested + hardnested) |
| `darkside` | read-only | Recover one key via PRNG weakness |
| `nested` | read-only | Recover key using known key (weak PRNG) |
| `hardnested` | read-only | Recover key using known key (hard PRNG) |
| `chk_keys` | read-only | Dictionary check against all sectors |
| `desfire_info` | read-only | DESFire tag details: UID, version, storage, apps, signature |
| `desfire_apps` | read-only | Enumerate DESFire applications and their auth requirements |
| `desfire_files` | read-only | List files in a DESFire application (usually requires auth) |
| `iclass_info` | read-only | iCLASS / PicoPass tag information (CSN, card type) |
| `iclass_rdbl` | read-only | Read an iCLASS block (blocks 0-4 usually readable without key) |
| `iclass_dump` | read-only | Dump iCLASS tag memory to file |
| `iclass_chk` | read-only | Check iCLASS keys from built-in dictionary |
| `iclass_loclass` | read-only | Recover iCLASS key via loclass attack |
| `iso15693_info` | read-only | ISO 15693 tag information (UID, type, manufacturer) |
| `iso15693_rdbl` | read-only | Read an ISO 15693 block |
| `iso15693_dump` | read-only | Dump ISO 15693 tag memory to file |
| `connect` | allowed-write | Validate PM3, create engagement folder |
| `disconnect` | allowed-write | Finalize command log |
| `sniff_start` | allowed-write | Start sniffing reader-tag communication (blocks until PM3 button press) |
| `sniff_stop` | allowed-write | Retrieve and decode sniffed trace data |
| `mf_wrbl` | approval-write | Write a MIFARE Classic block (requires confirmation) |
| `mf_restore` | approval-write | Restore full dump to MIFARE Classic tag (requires confirmation) |
| `iclass_wrbl` | approval-write | Write an iCLASS block (requires confirmation) |
| `iso15693_wrbl` | approval-write | Write an ISO 15693 block (requires confirmation) |

## Safety Model

Three tiers enforced at the MCP server boundary:

- **read-only:** full autonomy. Reading a tag does not alter it.
- **allowed-write:** autonomous, all calls logged. Creates engagement folders.
- **approval-write:** blocks until human confirms via `_confirmed` parameter. Writing overwrites tag data irreversibly.

## Architecture

```
pm3-mcp (server.py)
  |
  tools.py -> connection.py -> subprocess.run("pm3 -p PORT -c CMD")
  |                            parsers.py (text output -> structured dicts)
  |
Proxmark3 (iceman fw) via USB serial
```

- `connection.py` is the only module that calls subprocess. Each tool call runs one `pm3 -c` command (no persistent process).
- `parsers.py` handles the text output parsing, separated from tool logic. PM3 output format varies by command and iceman version.
- Port auto-detection scans `/dev/ttyACM*` when no port is specified.

## Project Integration

The `connect` tool accepts an optional `project_path` parameter. When provided (from project-mcp's `create_project`), engagement data is written to `<project_path>/pm3/` instead of creating a standalone folder. Omit it for standalone use.

## Known Constraints

- **~1s overhead per command:** each call connects/disconnects at USB level. Acceptable for identification workflows.
- **Output parsing fragility:** PM3 output format changes between iceman releases. Parsers may need updates on firmware upgrade.
- **Exclusive device access:** only one client can use the PM3 at a time.
- **Tag must be on the antenna:** RFID/NFC requires physical proximity (~5cm HF, ~10cm LF).

## Tests

```bash
pytest              # no PM3 hardware needed
pytest -m proxmark3 # integration tests, PM3 must be connected
```

## License

MIT
