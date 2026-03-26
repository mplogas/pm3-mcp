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


def parse_detect_tag(output: str) -> dict:
    """Parse output from 'auto' and return structured detection with protocol routing.

    Returns:
        found: bool
        frequency: "hf" | "lf" | None
        protocol: str (e.g. "mifare_classic", "mifare_desfire", "hid_prox", "em410x",
                       "iso15693", "iclass", "felica", "mifare_ultralight", etc.)
        uid: str or None
        tag_type: str or None (human-readable, e.g. "MIFARE Classic 1K")
        details: dict (protocol-specific: atqa, sak, prng, facility_code, card_number, etc.)
        suggested_tools: list of str (which pm3-mcp tools to call next)
        raw: full output
    """
    details = {}
    uid = None
    tag_type = None
    protocol = None
    frequency = None
    suggested_tools = []

    # -- HF: MIFARE Classic --
    if "MIFARE Classic" in output:
        frequency = "hf"
        protocol = "mifare_classic"
        uid_match = re.search(r"UID:\s*([0-9A-Fa-f ]+?)(?:\s*\(|$)", output, re.MULTILINE)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        atqa_match = re.search(r"ATQA:\s*([0-9A-Fa-f ]+)", output)
        sak_match = re.search(r"SAK:\s*([0-9A-Fa-f]+)", output)
        prng_match = re.search(r"Prng detection[.]+\s*(\w+)", output)
        magic_match = re.search(r"Magic capabilities[.]+\s*(.+)", output)

        # Determine 1K vs 4K
        if "Classic 4K" in output or "Classic 4k" in output:
            tag_type = "MIFARE Classic 4K"
        elif "Classic 1K" in output or "Classic 1k" in output:
            tag_type = "MIFARE Classic 1K"
        else:
            tag_type = "MIFARE Classic"

        details["atqa"] = atqa_match.group(1).strip().replace(" ", "") if atqa_match else None
        details["sak"] = sak_match.group(1) if sak_match else None
        details["prng"] = prng_match.group(1).lower() if prng_match else None
        details["magic"] = magic_match.group(1).strip() if magic_match else None

        # Static nonce detection
        if "Static nonce" in output:
            details["static_nonce"] = "yes" in output.split("Static nonce")[1][:20].lower()

        suggested_tools = ["hf_info", "chk_keys", "autopwn", "read_block", "dump_tag"]

    # -- HF: MIFARE DESFire --
    elif "DESFire" in output:
        frequency = "hf"
        protocol = "mifare_desfire"
        uid_match = re.search(r"UID:\s*([0-9A-Fa-f ]+?)(?:\s*\(|$)", output, re.MULTILINE)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        if "EV3" in output:
            tag_type = "MIFARE DESFire EV3"
        elif "EV2" in output:
            tag_type = "MIFARE DESFire EV2"
        elif "EV1" in output:
            tag_type = "MIFARE DESFire EV1"
        else:
            tag_type = "MIFARE DESFire"

        sak_match = re.search(r"SAK:\s*([0-9A-Fa-f]+)", output)
        details["sak"] = sak_match.group(1) if sak_match else None
        details["has_ats"] = "ATS:" in output

        suggested_tools = ["desfire_info", "desfire_apps"]

    # -- HF: MIFARE Ultralight --
    elif "Ultralight" in output or "NTAG" in output:
        frequency = "hf"
        protocol = "mifare_ultralight"
        uid_match = re.search(r"UID:\s*([0-9A-Fa-f ]+?)(?:\s*\(|$)", output, re.MULTILINE)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        if "NTAG" in output:
            ntag_match = re.search(r"(NTAG\d+)", output)
            tag_type = ntag_match.group(1) if ntag_match else "NTAG"
        else:
            tag_type = "MIFARE Ultralight"
        suggested_tools = ["hf_info"]

    # -- HF: ISO 15693 --
    elif "ISO 15693" in output or "Valid ISO 15693" in output:
        frequency = "hf"
        protocol = "iso15693"
        uid_match = re.search(r"UID[.]*\s*([0-9A-Fa-f ]+)", output)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        type_match = re.search(r"TYPE MATCH\s+(.+?)(?:\n|$)", output)
        tag_type = type_match.group(1).strip() if type_match else "ISO 15693"
        suggested_tools = ["hf_info"]

    # -- HF: iCLASS --
    elif "iCLASS" in output or "PicoPass" in output:
        frequency = "hf"
        protocol = "iclass"
        tag_type = "iCLASS / PicoPass"
        uid_match = re.search(r"CSN:\s*([0-9A-Fa-f ]+)", output)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        suggested_tools = ["hf_info"]

    # -- HF: FeliCa --
    elif "FeliCa" in output and "found" in output.lower():
        frequency = "hf"
        protocol = "felica"
        tag_type = "FeliCa"
        uid_match = re.search(r"IDm:\s*([0-9A-Fa-f ]+)", output)
        uid = uid_match.group(1).strip().replace(" ", "") if uid_match else None
        suggested_tools = ["hf_info"]

    # -- LF: HID Prox --
    elif "HID Prox" in output or "Valid HID Prox" in output:
        frequency = "lf"
        protocol = "hid_prox"
        tag_type = "HID Prox"
        fc_match = re.search(r"FC:\s*(\d+)", output)
        cn_match = re.search(r"CN:\s*(\d+)", output)
        raw_match = re.search(r"raw:\s*([0-9A-Fa-f]+)", output)
        details["facility_code"] = int(fc_match.group(1)) if fc_match else None
        details["card_number"] = int(cn_match.group(1)) if cn_match else None
        details["raw"] = raw_match.group(1) if raw_match else None
        uid = details.get("raw")
        suggested_tools = ["lf_info"]

    # -- LF: EM410x --
    elif "EM 410x" in output or "EM410x" in output:
        frequency = "lf"
        protocol = "em410x"
        tag_type = "EM410x"
        id_match = re.search(r"EM 410x ID\s+([0-9A-Fa-f]+)", output)
        uid = id_match.group(1) if id_match else None
        suggested_tools = ["lf_info"]

    # -- LF: Indala --
    elif "Indala" in output:
        frequency = "lf"
        protocol = "indala"
        tag_type = "Indala"
        fc_match = re.search(r"FC:\s*(\d+)", output)
        cn_match = re.search(r"CN:\s*(\d+)", output)
        details["facility_code"] = int(fc_match.group(1)) if fc_match else None
        details["card_number"] = int(cn_match.group(1)) if cn_match else None
        suggested_tools = ["lf_info"]

    found = protocol is not None

    return {
        "found": found,
        "frequency": frequency,
        "protocol": protocol,
        "uid": uid,
        "tag_type": tag_type,
        "details": details,
        "suggested_tools": suggested_tools,
        "raw": output,
    }


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


def parse_desfire_info(output: str) -> dict:
    """Parse output from 'hf mfdes info'.

    Returns:
        found: bool
        uid: str or None
        batch: str or None
        production: str or None
        product_type: str or None
        hw_version: str or None (e.g. "DESFire EV2")
        storage_bytes: int
        free_bytes: int
        signature_ok: bool
        app_count: int
        app_ids: list of str
        picc_auth: dict of auth method -> bool
        key_type: str or None (e.g. "AES")
        error: str or None
    """
    if "Can't select card" in output:
        return {
            "found": False,
            "error": "No DESFire tag detected. Check card positioning.",
        }

    uid = _extract(r"UID:\s*([0-9A-Fa-f ]+)", output)
    batch = _extract(r"Batch number:\s*([0-9A-Fa-f ]+)", output)
    production = _extract(r"Production date:\s*(.+)", output)
    product_type = _extract(r"Product type:\s*(.+)", output)

    # Hardware version: "Version: 12.0 ( DESFire EV2 )"
    hw_version = _extract(r"Version:\s*[\d.]+ \(\s*(.+?)\s*\)", output)

    # Storage: "Storage size: 0x1A ( 8192 bytes )"
    storage_match = re.search(r"Storage size:.*?\(\s*(\d+)\s*bytes\s*\)", output)
    storage_bytes = int(storage_match.group(1)) if storage_match else 0

    # Free memory: "Available free memory on card... 3328 bytes"
    free_match = re.search(r"free memory.*?(\d+)\s*bytes", output)
    free_bytes = int(free_match.group(1)) if free_match else 0

    # Signature verification
    signature_ok = "Signature verification: successful" in output

    # App count and IDs
    app_count_match = re.search(r"#\s*applications[.]*\s*(\d+)", output)
    app_count = int(app_count_match.group(1)) if app_count_match else 0

    app_ids = re.findall(r"AID list.*?found.*?\n((?:\[\+\]\s+[0-9A-Fa-f]+.*\n?)+)", output)
    aids = []
    if app_ids:
        aids = re.findall(r"([0-9A-Fa-f]{4,6})", app_ids[0])

    # PICC-level auth methods
    picc_auth = {}
    for m in re.finditer(r"Auth\s*([\w .]+?)\s*\.+\s*(YES|NO)", output):
        picc_auth[m.group(1).strip()] = m.group(2) == "YES"

    # Key type
    key_type = _extract(r"Key type[.]*\s*(\w+)", output)

    return {
        "found": True,
        "uid": uid.replace(" ", "") if uid else None,
        "batch": batch.strip() if batch else None,
        "production": production.strip() if production else None,
        "product_type": product_type.strip() if product_type else None,
        "hw_version": hw_version,
        "storage_bytes": storage_bytes,
        "free_bytes": free_bytes,
        "signature_ok": signature_ok,
        "app_count": app_count,
        "app_ids": aids,
        "picc_auth": picc_auth,
        "key_type": key_type,
        "error": None,
    }


def _extract(pattern: str, text: str) -> str | None:
    """Extract first group from a regex match, or None."""
    m = re.search(pattern, text)
    return m.group(1) if m else None


def parse_desfire_apps(output: str) -> dict:
    """Parse output from 'hf mfdes lsapp --no-auth'.

    Returns:
        app_count: int
        apps: list of {aid, iso_id, description, auth_methods}
    """
    apps = []

    # Split on "Application ID" lines
    app_blocks = re.split(r"(?=\[\+\] Application ID)", output)
    for block in app_blocks:
        aid_match = re.search(r"Application ID[.]*\s*0x([0-9A-Fa-f]+)", block)
        if not aid_match:
            continue

        aid = aid_match.group(1).upper()
        iso_id = _extract(r"ISO id[.]*\s*0x([0-9A-Fa-f]+)", block)
        desc = _extract(r"DF AID Function[.]*\s*\S+\s*:\s*(.+)", block)

        auth_methods = {}
        for m in re.finditer(r"Auth\s*([\w .]+?)\s*\.+\s*(YES|NO)", block):
            auth_methods[m.group(1).strip()] = m.group(2) == "YES"

        apps.append({
            "aid": aid,
            "iso_id": iso_id,
            "description": desc.strip() if desc else None,
            "auth_methods": auth_methods,
        })

    app_count_match = re.search(r"#\s*applications[.]*\s*(\d+)", output)
    app_count = int(app_count_match.group(1)) if app_count_match else len(apps)

    return {
        "app_count": app_count,
        "apps": apps,
    }


def parse_desfire_files(output: str) -> dict:
    """Parse output from 'hf mfdes lsfiles --no-auth --aid <AID>'.

    Returns:
        success: bool
        files: list of file info dicts (if accessible)
        error: str or None
    """
    if "GetFileIDList command error" in output or "error" in output.lower():
        return {
            "success": False,
            "files": [],
            "error": "Authentication required to list files in this application.",
        }

    # If we get here, files were listed (rare without auth)
    files = []
    # Parse file entries if present (format varies)
    for m in re.finditer(r"File ID[.]*\s*(\d+)", output):
        files.append({"file_id": int(m.group(1))})

    return {
        "success": True,
        "files": files,
        "error": None,
    }


def parse_iclass_info(output: str) -> dict:
    """Parse output from 'hf iclass info'.

    Returns:
        found: bool
        csn: str or None (Card Serial Number / UID)
        card_type: str or None
        raw: full output
        error: str or None
    """
    if "no tag found" in output.lower() or "can't select" in output.lower():
        return {
            "found": False,
            "csn": None,
            "card_type": None,
            "error": "No iCLASS tag detected.",
            "raw": output,
        }

    csn = _extract(r"CSN:\s*([0-9A-Fa-f ]+)", output)
    if not csn:
        csn = _extract(r"Serial number:\s*([0-9A-Fa-f ]+)", output)

    card_type = _extract(r"Card type:\s*(.+)", output)
    if not card_type:
        # Try alternative format
        card_type = _extract(r"Type:\s*(.+?)(?:\n|$)", output)

    return {
        "found": csn is not None,
        "csn": csn.replace(" ", "") if csn else None,
        "card_type": card_type.strip() if card_type else None,
        "error": None,
        "raw": output,
    }


def parse_iclass_rdbl(output: str) -> dict:
    """Parse output from 'hf iclass rdbl'.

    Returns:
        success: bool
        block: int or None
        hex: str or None
        ascii: str or None
        bytes: int or None
        error: str or None
    """
    # Success: block data line with hex bytes
    # Various formats: "Block XX: AA BB CC DD EE FF GG HH"
    block_match = re.search(
        r"[Bb]lock\s+(\d+)[:\s]+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)",
        output,
    )
    if block_match:
        block_num = int(block_match.group(1))
        hex_str = block_match.group(2).strip()
        byte_vals = [int(b, 16) for b in hex_str.split()]
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in byte_vals)
        return {
            "success": True,
            "block": block_num,
            "hex": hex_str,
            "ascii": ascii_text,
            "bytes": len(byte_vals),
            "error": None,
        }

    # Also try table format: [=] N | HH HH HH ... | ascii
    table_match = re.search(
        r"\[=\]\s+(\d+)\s+\|\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s+\|",
        output,
    )
    if table_match:
        block_num = int(table_match.group(1))
        hex_str = table_match.group(2).strip()
        byte_vals = [int(b, 16) for b in hex_str.split()]
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in byte_vals)
        return {
            "success": True,
            "block": block_num,
            "hex": hex_str,
            "ascii": ascii_text,
            "bytes": len(byte_vals),
            "error": None,
        }

    error = None
    if "auth" in output.lower() or "key" in output.lower():
        error = "Authentication failed. Wrong key or key not provided."
    elif "no tag" in output.lower():
        error = "No tag detected."
    else:
        error = "Block read failed."

    return {
        "success": False,
        "block": None,
        "hex": None,
        "ascii": None,
        "bytes": None,
        "error": error,
    }


def parse_iso15693_info(output: str) -> dict:
    """Parse output from 'hf 15 info'.

    Returns:
        found: bool
        uid: str or None
        tag_type: str or None
        manufacturer: str or None
        raw: full output
        error: str or None
    """
    if "no tag found" in output.lower():
        return {
            "found": False,
            "uid": None,
            "tag_type": None,
            "manufacturer": None,
            "error": "No ISO 15693 tag detected.",
            "raw": output,
        }

    uid = _extract(r"UID[.:\s]+([0-9A-Fa-f ]+)", output)
    # Check "TYPE MATCH" first (more specific), then fall back to "TYPE:"
    tag_type = _extract(r"TYPE MATCH\s+(.+?)(?:\n|$)", output)
    if not tag_type:
        tag_type = _extract(r"TYPE[:\s]+(.+?)(?:\n|$)", output)

    manufacturer = _extract(r"(?:Manufacturer|Vendor)[:\s]+(.+?)(?:\n|$)", output)
    if not manufacturer and tag_type:
        # Extract manufacturer from TYPE MATCH line: "NXP (Philips); IC SL2..."
        mfr_match = re.search(r"([A-Z][A-Za-z]+(?:\s*\([^)]+\))?)", tag_type)
        if mfr_match:
            manufacturer = mfr_match.group(1)

    return {
        "found": uid is not None,
        "uid": uid.replace(" ", "") if uid else None,
        "tag_type": tag_type.strip() if tag_type else None,
        "manufacturer": manufacturer.strip() if manufacturer else None,
        "error": None,
        "raw": output,
    }


def parse_iso15693_rdbl(output: str) -> dict:
    """Parse output from 'hf 15 rdbl'.

    Returns:
        success: bool
        block: int or None
        hex: str or None
        bytes: int or None
        error: str or None
    """
    # Success format varies, look for hex data after block number
    block_match = re.search(
        r"[Bb]lock\s+(\d+)[:\s]+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)",
        output,
    )
    if block_match:
        block_num = int(block_match.group(1))
        hex_str = block_match.group(2).strip()
        return {
            "success": True,
            "block": block_num,
            "hex": hex_str,
            "bytes": len(hex_str.split()),
            "error": None,
        }

    # ISO 15693 table format: [=] HH HH HH HH | N | ascii
    # The hex data comes first, then | lock_flag | ascii
    iso_table_match = re.search(
        r"\[=\]\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s+\|",
        output,
    )
    if iso_table_match:
        hex_str = iso_table_match.group(1).strip()
        # Extract block number from the header line: "#  N"
        blk_match = re.search(r"#\s+(\d+)", output)
        block_num = int(blk_match.group(1)) if blk_match else 0
        return {
            "success": True,
            "block": block_num,
            "hex": hex_str,
            "bytes": len(hex_str.split()),
            "error": None,
        }

    # Generic table format: [=] N | HH HH HH ... | ascii
    table_match = re.search(
        r"\[=\]\s+(\d+)\s+\|\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s+\|",
        output,
    )
    if table_match:
        block_num = int(table_match.group(1))
        hex_str = table_match.group(2).strip()
        return {
            "success": True,
            "block": block_num,
            "hex": hex_str,
            "bytes": len(hex_str.split()),
            "error": None,
        }

    return {
        "success": False,
        "block": None,
        "hex": None,
        "bytes": None,
        "error": "Block read failed.",
    }


def parse_iclass_chk(output: str) -> dict:
    """Parse output from 'hf iclass chk'.

    Returns:
        found: bool
        key: hex string if found
        error: str or None
    """
    # Success: [+] Found valid key AAXXXXXXXXXX
    key_match = re.search(r"[Ff]ound valid key\s+([0-9A-Fa-f]+)", output)
    if key_match:
        return {
            "found": True,
            "key": key_match.group(1).upper(),
            "error": None,
        }

    # Also try: "key : XXXX"
    key_match2 = re.search(r"key\s*:\s*([0-9A-Fa-f]{16})", output)
    if key_match2:
        return {
            "found": True,
            "key": key_match2.group(1).upper(),
            "error": None,
        }

    return {
        "found": False,
        "key": None,
        "error": "No matching key found in dictionary.",
    }


def parse_iclass_loclass(output: str) -> dict:
    """Parse output from 'hf iclass loclass'.

    Returns:
        success: bool
        key: hex string if recovered
        error: str or None
    """
    # Success: key recovered
    key_match = re.search(r"[Kk]ey\s*:\s*([0-9A-Fa-f]{16})", output)
    if key_match:
        return {
            "success": True,
            "key": key_match.group(1).upper(),
            "error": None,
        }

    # Also: "Found key:"
    key_match2 = re.search(r"[Ff]ound key[:\s]+([0-9A-Fa-f]+)", output)
    if key_match2:
        return {
            "success": True,
            "key": key_match2.group(1).upper(),
            "error": None,
        }

    error = "loclass attack failed."
    if "no file" in output.lower() or "not found" in output.lower():
        error = "Trace file not found. Run 'hf iclass sim -t 2' first to capture NR/MAC pairs."

    return {
        "success": False,
        "key": None,
        "error": error,
    }
