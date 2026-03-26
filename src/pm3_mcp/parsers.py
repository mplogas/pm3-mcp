"""Output parsers for Proxmark3 iceman firmware commands.

Pure functions: text in, dict out. No subprocess calls.

PM3 line prefixes:
  [+] info/success
  [#] data
  [=] verbose/status
  [!] warning
  [-] failure
"""

import re


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes and spinner characters from text.

    Strips:
    - ANSI color/style codes (ESC [ ... m and related sequences)
    - Spinner characters: | / \\
    """
    # ANSI escape sequences: ESC followed by [ and parameter/intermediate bytes then a final byte
    ansi_re = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    text = ansi_re.sub("", text)
    # Remove spinner sequences: [|] [/] [\] used in PM3 progress indicators.
    # Only strip when they appear as bracketed spinner chars, not bare | in tables.
    text = re.sub(r"\[[\|/\\]\]", "", text)
    return text


def parse_hw_status(output: str) -> dict:
    """Parse output from 'pm3 -c hw status'.

    Returns:
        fpga_image: str -- FPGA image name/description
        flash_memory_kb: int -- flash size in kilobytes
        unique_id: str -- device unique ID (hex string)
        dictionaries: dict[str, int] -- name -> key count
        standalone_mode: str -- installed standalone mode description
        transfer_speed_bps: int -- measured transfer speed in bytes/sec
    """
    result: dict = {
        "fpga_image": None,
        "flash_memory_kb": None,
        "unique_id": None,
        "dictionaries": {},
        "standalone_mode": None,
        "transfer_speed_bps": None,
    }

    for line in output.splitlines():
        stripped = line.strip()

        # FPGA image: "[#]   mode.................... fpga_pm3_lf.ncd image ..."
        m = re.search(r"\[#\]\s+mode\.+\s+(.+)", stripped)
        if m:
            result["fpga_image"] = m.group(1).strip()
            continue

        # Flash memory size: "[#]   Memory size............. 2048 Kb ( 32 pages * 64k )"
        m = re.search(r"\[#\]\s+Memory size\.+\s+(\d+)\s+Kb", stripped)
        if m:
            result["flash_memory_kb"] = int(m.group(1))
            continue

        # Unique ID: "[#]   Unique ID (be).......... 0x0B33383153325041"
        m = re.search(r"\[#\]\s+Unique ID.*?\.\.\.\.\s+(0x[0-9A-Fa-f]+)", stripped)
        if m:
            result["unique_id"] = m.group(1).strip()
            continue

        # Transfer speed: "[#]   Transfer Speed PM3 -> Client... 502784 bytes/s"
        m = re.search(r"\[#\]\s+Transfer Speed PM3.*?(\d+)\s+bytes/s", stripped)
        if m:
            result["transfer_speed_bps"] = int(m.group(1))
            continue

        # Standalone mode: "[#]   LF HID26 standalone - aka SamyRun (Samy Kamkar)"
        m = re.search(r"\[#\]\s+(.*standalone.*)", stripped, re.IGNORECASE)
        if m:
            result["standalone_mode"] = m.group(1).strip()
            continue

        # Dictionary entries: "[#]   Mifare... 2375 keys - dict_mf.bin"
        m = re.search(r"\[#\]\s+(\w[\w-]*)[\.\s]+(\d+)\s+keys\s+-\s+\S+", stripped)
        if m:
            name = m.group(1).lower().rstrip(".")
            count = int(m.group(2))
            result["dictionaries"][name] = count
            continue

    return result


def parse_hf_search(output: str) -> dict:
    """Parse output from 'pm3 -c hf search'.

    Returns:
        found: bool
        uid: str or None
        tag_type: str or None
        raw: str
    """
    result: dict = {
        "found": False,
        "uid": None,
        "tag_type": None,
        "raw": output,
    }

    in_types_section = False
    lines = output.splitlines()
    for line in lines:
        stripped = line.strip()

        # Success indicators
        if re.search(r"\[\+\].*Valid.*tag found", stripped, re.IGNORECASE):
            result["found"] = True
            in_types_section = False
            continue

        # UID line: "[+]  UID: 04 A3 B2 C1"
        m = re.search(r"\[\+\]\s+UID:\s+([0-9A-Fa-f ]+)", stripped)
        if m:
            result["uid"] = m.group(1).strip().replace(" ", "")
            result["found"] = True
            in_types_section = False
            continue

        # Start of possible types section
        if re.search(r"\[\+\]\s+Possible types", stripped):
            in_types_section = True
            continue

        # Lines within possible types section
        if in_types_section and re.match(r"\[\+\]", stripped):
            type_name = re.sub(r"^\[\+\]\s+", "", stripped).strip()
            # Stop collecting if we hit a non-type line
            if re.match(r"(Prng|Magic|Valid|SAK|ATQA|UID|Block)", type_name, re.IGNORECASE):
                in_types_section = False
            elif type_name and result["tag_type"] is None:
                result["tag_type"] = type_name
                continue

    # No tag: check explicit failure message
    if re.search(r"No known.*tags found", output, re.IGNORECASE):
        result["found"] = False

    return result


def parse_lf_search(output: str) -> dict:
    """Parse output from 'pm3 -c lf search'.

    Returns:
        found: bool
        tag_type: str or None (e.g. "EM410x")
        tag_id: str or None
        raw: str
    """
    result: dict = {
        "found": False,
        "tag_type": None,
        "tag_id": None,
        "raw": output,
    }

    for line in output.splitlines():
        stripped = line.strip()

        # "Couldn't identify a chipset" -> not found
        if re.search(r"couldn.t identify", stripped, re.IGNORECASE):
            result["found"] = False
            continue

        # Valid tag found lines
        if re.search(r"\[\+\].*Valid.*found", stripped, re.IGNORECASE):
            result["found"] = True
            continue

        # EM410x ID line: "[+] EM 410x ID 0102030405"
        m = re.search(r"\[\+\]\s+EM\s*410x\s+ID\s+([0-9A-Fa-f]+)", stripped, re.IGNORECASE)
        if m:
            result["found"] = True
            result["tag_type"] = "EM410x"
            result["tag_id"] = m.group(1).strip()
            continue

        # Generic "Tag Type:" line
        m = re.search(r"Tag Type:\s*(.+)", stripped, re.IGNORECASE)
        if m and result["tag_type"] is None:
            result["tag_type"] = m.group(1).strip()
            continue

        # Chipset detection line: "Chipset detection: EM4100/EM4102"
        m = re.search(r"Chipset detection:\s*(.+)", stripped, re.IGNORECASE)
        if m and result["tag_type"] is None:
            # Infer EM410x from chipset family
            chipset = m.group(1).strip()
            if re.search(r"EM41", chipset, re.IGNORECASE):
                result["tag_type"] = "EM410x"
            continue

    return result


def parse_hf_14a_info(output: str) -> dict:
    """Parse output from 'pm3 -c hf 14a info'.

    Returns:
        uid: str -- hex UID, no spaces (e.g. "04A3B2C1")
        atqa: str -- 4-char hex (e.g. "0004")
        sak: str -- 2-char hex (e.g. "08")
        possible_types: list[str]
        prng: str or None (e.g. "weak", "hard", "static")
        magic: str or None -- magic capabilities description
        raw: str
    """
    result: dict = {
        "uid": None,
        "atqa": None,
        "sak": None,
        "possible_types": [],
        "prng": None,
        "magic": None,
        "raw": output,
    }

    in_types_section = False

    for line in output.splitlines():
        stripped = line.strip()

        # UID: "[+]  UID: 04 A3 B2 C1"
        m = re.search(r"\[\+\]\s+UID:\s+([0-9A-Fa-f ]+)", stripped)
        if m:
            result["uid"] = m.group(1).strip().replace(" ", "").upper()
            in_types_section = False
            continue

        # ATQA: "[+] ATQA: 00 04"
        m = re.search(r"\[\+\]\s+ATQA:\s+([0-9A-Fa-f ]+)", stripped)
        if m:
            result["atqa"] = m.group(1).strip().replace(" ", "").upper()
            in_types_section = False
            continue

        # SAK: "[+]  SAK: 08 [2]"
        m = re.search(r"\[\+\]\s+SAK:\s+([0-9A-Fa-f]+)", stripped)
        if m:
            result["sak"] = m.group(1).strip().upper()
            in_types_section = False
            continue

        # Start of possible types section
        if re.search(r"\[\+\]\s+Possible types", stripped):
            in_types_section = True
            continue

        # Lines within possible types section: "[+]    MIFARE Classic 1K"
        if in_types_section and re.match(r"\[\+\]\s+\S", stripped):
            type_name = re.sub(r"^\[\+\]\s+", "", stripped).strip()
            # Stop collecting if we hit a non-type line (Prng, Magic, etc.)
            if re.match(r"(Prng|Magic|Valid|SAK|ATQA|UID|Block)", type_name, re.IGNORECASE):
                in_types_section = False
            else:
                result["possible_types"].append(type_name)
                continue

        # Prng: "[+] Prng detection....... weak"
        m = re.search(r"\[\+\]\s+Prng detection[.\s]+(\w+)", stripped)
        if m:
            result["prng"] = m.group(1).strip().lower()
            in_types_section = False
            continue

        # Magic capabilities: "[+] Magic capabilities... Gen 1a"
        m = re.search(r"\[\+\]\s+Magic capabilities[.\s]+(.+)", stripped)
        if m:
            result["magic"] = m.group(1).strip()
            in_types_section = False
            continue

    return result


def parse_block_read(output: str) -> dict:
    """Parse output from 'pm3 -c hf mf rdbl'.

    On success:
        success: True
        block: int
        hex: str -- space-separated hex bytes
        ascii: str
        bytes: int -- number of bytes

    On auth failure:
        success: False
        block: int (extracted from command line if present)
        error: str
    """
    result: dict = {
        "success": False,
        "block": None,
        "hex": None,
        "ascii": None,
        "bytes": None,
        "error": None,
    }

    for line in output.splitlines():
        stripped = line.strip()

        # Extract block number from command invocation line
        # "[usb|script] pm3 --> hf mf rdbl --blk 0 -k ..."
        m = re.search(r"hf mf rdbl\s+.*?(?:--blk|-b)\s+(\d+)", stripped)
        if m:
            result["block"] = int(m.group(1))
            continue

        # Table format (current iceman): "[=]   0 | AD 6F EF EC ... | ascii"
        m = re.search(r"\[=\]\s+(\d+)\s+\|\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s+\|", stripped)
        if m:
            result["success"] = True
            result["block"] = int(m.group(1))
            hex_str = m.group(2).strip()
            result["hex"] = hex_str
            byte_vals = [int(b, 16) for b in hex_str.split()]
            result["bytes"] = len(byte_vals)
            result["ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in byte_vals
            )
            continue

        # Legacy format: "[+] Block 0: 04 A3 B2 C1 ..."
        m = re.search(r"\[\+\]\s+Block\s+(\d+):\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)", stripped)
        if m:
            result["success"] = True
            result["block"] = int(m.group(1))
            hex_str = m.group(2).strip()
            result["hex"] = hex_str
            # Build bytes list for count and ASCII
            byte_vals = [int(b, 16) for b in hex_str.split()]
            result["bytes"] = len(byte_vals)
            result["ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in byte_vals
            )
            continue

        # Auth failure: "[-] Auth error"
        m = re.search(r"\[-\]\s+(.+)", stripped)
        if m:
            result["error"] = m.group(1).strip()
            result["success"] = False
            continue

    return result


def parse_dump_result(output: str, dump_path: str) -> dict:
    """Parse output from 'pm3 -c hf mf dump'.

    Returns:
        success: bool
        dump_path: str -- the dump_path argument passed in
        output_file: str or None -- filename saved
        raw: str
    """
    result: dict = {
        "success": False,
        "dump_path": dump_path,
        "output_file": None,
        "raw": output,
    }

    for line in output.splitlines():
        stripped = line.strip()

        # Saved file line: "[=] Saved to binary file hf-mf-04A3B2C1-dump.bin"
        m = re.search(r"\[=\]\s+Saved to (?:binary|json) file\s+(\S+)", stripped)
        if m:
            # Prefer binary (.bin) file as the canonical output
            fname = m.group(1).strip()
            if result["output_file"] is None or fname.endswith(".bin"):
                result["output_file"] = fname
            continue

        # Success: "[+] Dumped N blocks (M bytes)"
        if re.search(r"\[\+\]\s+Dumped\s+\d+\s+blocks", stripped):
            result["success"] = True
            continue

        # Explicit failure
        if re.search(r"\[-\]\s+Dump failed", stripped, re.IGNORECASE):
            result["success"] = False
            continue

    return result


def sector_to_trailer(sector: int) -> int:
    """Convert a MIFARE Classic sector number to its trailer block number.

    1K sectors 0-15: trailer at (sector * 4 + 3)
    4K sectors 0-31: same as 1K
    4K sectors 32-39: 16 blocks each, trailer at (128 + (sector - 32) * 16 + 15)
    """
    if sector < 32:
        return sector * 4 + 3
    return 128 + (sector - 32) * 16 + 15


def parse_autopwn(output: str) -> dict:
    """Parse output from 'hf mf autopwn'.

    Returns:
        keys: list of {sector, key_a, key_b, method_a, method_b}
        dump_files: list of file paths generated
        execution_time_s: int
        complete: bool (all sectors recovered)
        error: str or None (no tag, communication errors, etc.)
        raw: full output
    """
    # Check for early failures
    if "No tag detected" in output:
        return {
            "keys": [],
            "dump_files": [],
            "execution_time_s": 0,
            "complete": False,
            "error": "No tag detected. Check card positioning on the antenna.",
            "raw": output,
        }

    keys = []
    dump_files = []
    execution_time_s = 0

    # Primary: parse the summary key table (printed on success/partial success):
    # [+]  000 | 003 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
    key_table_re = re.compile(
        r"\[\+\]\s+(\d+)\s+\|\s+\d+\s+\|\s+([0-9A-Fa-f-]+)\s+\|\s+(\w)\s+\|\s+([0-9A-Fa-f-]+)\s+\|\s+(\w)"
    )
    for m in key_table_re.finditer(output):
        sector = int(m.group(1))
        key_a = m.group(2) if m.group(2) != "------------" else None
        method_a = m.group(3)
        key_b = m.group(4) if m.group(4) != "------------" else None
        method_b = m.group(5)
        keys.append({
            "sector": sector,
            "key_a": key_a,
            "key_b": key_b,
            "method_a": method_a,
            "method_b": method_b,
        })

    # Fallback: if no summary table, extract from individual key recovery lines.
    # These are printed as keys are found, before the summary:
    # [+] Target sector   0 key type A -- found valid key [ FFFFFFFFFFFF ]
    if not keys:
        individual_re = re.compile(
            r"Target sector\s+(\d+)\s+key type\s+(\w)\s+--\s+found valid key\s+\[\s*([0-9A-Fa-f]+)\s*\]"
        )
        sector_keys: dict[int, dict] = {}
        for m in individual_re.finditer(output):
            sector = int(m.group(1))
            key_type = m.group(2).upper()
            key_val = m.group(3)

            if sector not in sector_keys:
                sector_keys[sector] = {
                    "sector": sector,
                    "key_a": None,
                    "key_b": None,
                    "method_a": None,
                    "method_b": None,
                }

            if key_type == "A":
                sector_keys[sector]["key_a"] = key_val
                sector_keys[sector]["method_a"] = "?"
            else:
                sector_keys[sector]["key_b"] = key_val
                sector_keys[sector]["method_b"] = "?"

        keys = sorted(sector_keys.values(), key=lambda k: k["sector"])

    # Parse dump file paths
    for m in re.finditer(r"(?:dumped to|Saved.*?to.*?file)\s+`?([^\s`]+)`?", output):
        dump_files.append(m.group(1))

    # Parse execution time
    time_match = re.search(r"Autopwn execution time:\s+(\d+)\s+seconds?", output)
    if time_match:
        execution_time_s = int(time_match.group(1))

    # Detect errors
    error = None
    if "No match for the First_Byte_Sum" in output:
        error = (
            "Hardnested attack failed (First_Byte_Sum mismatch). "
            "Card may have non-standard crypto or poor RF coupling. "
            "Try repositioning the card or using a different known key."
        )
    elif "Auth error" in output and not keys:
        error = "Authentication errors during nonce collection. Check card positioning."

    # Complete if we have all 16 sectors with both keys
    complete = len(keys) >= 16 and all(
        k["key_a"] is not None and k["key_b"] is not None for k in keys
    )

    return {
        "keys": keys,
        "dump_files": dump_files,
        "execution_time_s": execution_time_s,
        "complete": complete,
        "error": error,
        "raw": output,
    }


def parse_darkside(output: str) -> dict:
    """Parse output from 'hf mf darkside'.

    Returns:
        success: bool
        key: hex string if found
        error: failure reason if not
    """
    # Success: [+] Found valid key: A0A1A2A3A4A5
    key_match = re.search(r"Found valid key:\s*([0-9A-Fa-f]+)", output)
    if key_match:
        return {
            "success": True,
            "key": key_match.group(1).upper(),
            "error": None,
        }

    # Also check: Key found: XXXX (alternative format from brute force)
    key_match2 = re.search(r"Key found:\s*([0-9A-Fa-f]+)", output)
    if key_match2:
        return {
            "success": True,
            "key": key_match2.group(1).upper(),
            "error": None,
        }

    # Failure: extract error line
    error_match = re.search(r"\[-\]\s+(.+)", output)
    error_msg = error_match.group(1).strip() if error_match else "darkside attack failed"
    return {
        "success": False,
        "key": None,
        "error": error_msg,
    }


def parse_hardnested(output: str) -> dict:
    """Parse output from 'hf mf hardnested'.

    Returns:
        success: bool
        key: hex string if found
        target_sector: int (from the "found valid key" line)
        nonces: int (from the nonce count column)
        error: failure reason if not
    """
    # Success: Key found: 4D57414C5648
    key_match = re.search(r"Key found:\s*([0-9A-Fa-f]+)", output)
    # Also: [+] Target sector N key type X -- found valid key [ XXXX ]
    target_match = re.search(
        r"Target sector\s+(\d+)\s+key type\s+\w\s+--\s+found valid key\s+\[\s*([0-9A-Fa-f]+)\s*\]",
        output,
    )

    key = None
    target_sector = None

    if key_match:
        key = key_match.group(1).upper()
    if target_match:
        target_sector = int(target_match.group(1))
        if key is None:
            key = target_match.group(2).upper()

    if key:
        # Extract nonce count from last nonces column entry
        nonce_matches = re.findall(r"\|\s+(\d+)\s+\|", output)
        nonces = int(nonce_matches[-1]) if nonce_matches else 0

        return {
            "success": True,
            "key": key,
            "target_sector": target_sector,
            "nonces": nonces,
            "error": None,
        }

    error_match = re.search(r"\[-\]\s+(.+)", output)
    error_msg = error_match.group(1).strip() if error_match else "hardnested attack failed"
    return {
        "success": False,
        "key": None,
        "target_sector": target_sector,
        "nonces": 0,
        "error": error_msg,
    }


def parse_chk_keys(output: str) -> dict:
    """Parse output from 'hf mf chk'.

    Returns:
        keys: list of {sector, key_a, key_b} (None if not found)
        found_count: total keys found
        total_sectors: sectors checked
    """
    keys = []
    found_count = 0

    # Same table format as autopwn but with 1/0 instead of method codes
    # [+]  000 | 003 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
    # [+]  001 | 007 | ------------ | 0 | ------------ | 0
    key_table_re = re.compile(
        r"\[\+\]\s+(\d+)\s+\|\s+\d+\s+\|\s+([0-9A-Fa-f-]+)\s+\|\s+(\d)\s+\|\s+([0-9A-Fa-f-]+)\s+\|\s+(\d)"
    )
    for m in key_table_re.finditer(output):
        sector = int(m.group(1))
        key_a_raw = m.group(2)
        found_a = m.group(3) == "1"
        key_b_raw = m.group(4)
        found_b = m.group(5) == "1"

        key_a = key_a_raw if found_a and key_a_raw != "------------" else None
        key_b = key_b_raw if found_b and key_b_raw != "------------" else None

        if key_a:
            found_count += 1
        if key_b:
            found_count += 1

        keys.append({
            "sector": sector,
            "key_a": key_a,
            "key_b": key_b,
        })

    return {
        "keys": keys,
        "found_count": found_count,
        "total_sectors": len(keys),
    }
