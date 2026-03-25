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
    # Remove spinner characters -- these are standalone characters used in
    # progress indicators. Only strip when they appear as isolated spinner chars.
    # We strip all occurrences since they are noise in parsed output.
    text = re.sub(r"[|/\\]", "", text)
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
        # "[usb|script] pm3 --> hf mf rdbl -b 0 -k ..."
        m = re.search(r"hf mf rdbl\s+.*?-b\s+(\d+)", stripped)
        if m:
            result["block"] = int(m.group(1))
            continue

        # Success data line: "[+] Block 0: 04 A3 B2 C1 D4 08 04 00 62 63 64 65 66 67 68 69"
        m = re.search(r"\[\+\]\s+Block\s+(\d+):\s+([0-9A-Fa-f](?:\s+[0-9A-Fa-f]{2})+|[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)", stripped)
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
