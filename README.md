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
| `connect` | allowed-write | Validate PM3, create engagement folder |
| `disconnect` | allowed-write | Finalize command log |

## Safety Model

Three tiers enforced at the MCP server boundary:

- **read-only:** full autonomy. Reading a tag does not alter it.
- **allowed-write:** autonomous, all calls logged. Creates engagement folders.
- **approval-write:** reserved for future write/clone operations (no MVP tools). Writing overwrites tag data irreversibly.

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

## Known Constraints

- **~1s overhead per command:** each call connects/disconnects at USB level. Acceptable for identification workflows.
- **Output parsing fragility:** PM3 output format changes between iceman releases. Parsers may need updates on firmware upgrade.
- **Exclusive device access:** only one client can use the PM3 at a time.
- **Tag must be on the antenna:** RFID/NFC requires physical proximity (~5cm HF, ~10cm LF).

## Tests

```bash
pytest              # 109 tests, no PM3 hardware needed
pytest -m proxmark3 # integration tests, PM3 must be connected
```

## License

MIT
