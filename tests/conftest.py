"""Shared test fixtures for pm3-mcp tests.

Output strings are captured from a real Proxmark3 (iceman fw) device.
They are the ground truth for parser tests.
"""

import pytest


@pytest.fixture
def engagements_dir(tmp_path):
    """Temporary engagements directory for tests."""
    return tmp_path / "engagements"


@pytest.fixture
def hw_status_output():
    """Real output from 'pm3 -c hw status'."""
    return """[usb|script] pm3 --> hw status
[#] Memory
[#]   BigBuf_size............. 36948
[#]   Available memory........ 36948
[#] Tracing
[#]   tracing ................ 0
[#]   traceLen ............... 0
[#] Current FPGA image
[#]   mode.................... fpga_pm3_lf.ncd image 2s30vq100 25-03-2026 21:40:34
[#] Flash memory
[#]   Baudrate................ 24 MHz
[#]   Init.................... ok
[#]   Mfr ID / Dev ID......... 85 / 14
[#]   JEDEC Mfr ID / Dev ID... 85 / 6015
[#]   Memory size............. 2048 Kb ( 32 pages * 64k )
[#]   Unique ID (be).......... 0x0B33383153325041
[#] Smart card module (ISO 7816)
[#]   version................. ( fail )
[#] LF Sampling config
[#]   [q] divisor............. 95 ( 125.00 kHz )
[#]   [b] bits per sample..... 8
[#]   [d] decimation.......... 1
[#]   [a] averaging........... no
[#]   [t] trigger threshold... 0
[#]   [s] samples to skip..... 0
[#]
[#] LF T55XX config
[#]            [r]               [a]   [b]   [c]   [d]   [e]   [f]   [g]
[#]            mode            |start|write|write|write| read|write|write
[#]                            | gap | gap |  0  |  1  | gap |  2  |  3
[#] ---------------------------+-----+-----+-----+-----+-----+-----+------
[#] fixed bit length (default) |  29 |  17 |  15 |  47 |  15 | n/a | n/a |
[#]     long leading reference |  29 |  17 |  15 |  47 |  15 | n/a | n/a |
[#]               leading zero |  29 |  17 |  15 |  40 |  15 | n/a | n/a |
[#]    1 of 4 coding reference |  29 |  17 |  15 |  31 |  15 |  47 |  63 |
[#]
[#] HF 14a config
[#]   [a] Anticol override........... std    ( follow standard )
[#]   [b] BCC override............... std    ( follow standard )
[#]   [2] CL2 override............... std    ( follow standard )
[#]   [3] CL3 override............... std    ( follow standard )
[#]   [r] RATS override.............. std    ( follow standard )
[#]   [m] Magsafe polling............ disabled
[#]   [p] Polling loop annotation.... disabled 00000000000000000000000000000000
[#] HF 14b config
[#]   [p] Polling loop annotation.... disabled 00000000000000000000000000000000
[#] Transfer Speed
[#]   Sending packets to client...
[#]   Time elapsed................... 500ms
[#]   Bytes transferred.............. 251392
[#]   Transfer Speed PM3 -> Client... 502784 bytes/s
[#] Various
[#]   Max stack usage..... 5208 / 8480 bytes
[#]   Debug log level..... 1 ( error )
[#]   ToSendMax........... 6
[#]   ToSend BUFFERSIZE... 2308
[#]   Slow clock.......... 30400 Hz
[#] Installed StandAlone Mode
[#]   LF HID26 standalone - aka SamyRun (Samy Kamkar)
[#] Flash memory dictionary loaded
[#]   Mifare... 2375 keys - dict_mf.bin
[#]   T55xx.... 125 keys - dict_t55xx.bin
[#]   iClass... 29 keys - dict_iclass.bin
[#]   UL-C..... 0 keys - dict_mfulc.bin
[#]   UL-AES... 0 keys - dict_mfulaes.bin
[#]"""


@pytest.fixture
def hf_search_no_tag_output():
    """Real output from 'pm3 -c hf search' with no tag present."""
    return """[usb|script] pm3 --> hf search
[!] No known/supported 13.56 MHz tags found"""


@pytest.fixture
def lf_search_no_tag_output():
    """Real output from 'pm3 -c lf search' with no tag present."""
    return """[usb|script] pm3 --> lf search

[=] Note: False Positives ARE possible
[=]
[=] Checking for known tags...
[=]
[=] Searching for auth LF and special cases...
[=] Couldn't identify a chipset
[?] Hint: try `hf search` - since tag might not be LF"""


@pytest.fixture
def hf_14a_info_output():
    """Simulated output from 'pm3 -c hf 14a info' with a MIFARE Classic 1K tag."""
    return """[usb|script] pm3 --> hf 14a info
[+]  UID: 04 A3 B2 C1
[+] ATQA: 00 04
[+]  SAK: 08 [2]
[+] Possible types:
[+]    MIFARE Classic 1K
[+] Prng detection....... weak
[+] Magic capabilities... Gen 1a"""


@pytest.fixture
def hf_mf_rdbl_output():
    """Simulated output from 'pm3 -c hf mf rdbl -b 0'."""
    return """[usb|script] pm3 --> hf mf rdbl -b 0 -k FFFFFFFFFFFF --ka
[+] Block 0: 04 A3 B2 C1 D4 08 04 00 62 63 64 65 66 67 68 69"""


@pytest.fixture
def hf_mf_rdbl_auth_fail_output():
    """Simulated output from failed auth on block read."""
    return """[usb|script] pm3 --> hf mf rdbl -b 4 -k FFFFFFFFFFFF --ka
[-] Auth error"""


@pytest.fixture
def hf_search_found_output():
    """Simulated output from 'pm3 -c hf search' with a MIFARE Classic 1K tag present."""
    return """[usb|script] pm3 --> hf search
[+]  UID: 04 A3 B2 C1
[+] ATQA: 00 04
[+]  SAK: 08 [2]
[+] Possible types:
[+]    MIFARE Classic 1K
[+] Prng detection....... weak
[+] Magic capabilities... Gen 1a
[+] Valid ISO 14443-A tag found"""


@pytest.fixture
def lf_search_em410x_output():
    """Simulated output from 'pm3 -c lf search' with an EM410x tag present."""
    return """[usb|script] pm3 --> lf search

[=] Note: False Positives ARE possible
[=]
[=] Checking for known tags...
[=]
[+] EM 410x ID 0102030405

[+] Valid EM410x ID found!

Chipset detection: EM4100/EM4102
Tag Type: EM410x"""


@pytest.fixture
def dump_success_output():
    """Simulated output from a successful 'pm3 -c hf mf dump'."""
    return """[usb|script] pm3 --> hf mf dump
[+] Reading sector access bits...
[+] Generating binary file
[=] Saved to json file hf-mf-04A3B2C1-dump.json
[=] Saved to binary file hf-mf-04A3B2C1-dump.bin
[+] Dumped 64 blocks (1024 bytes)"""


@pytest.fixture
def dump_fail_output():
    """Simulated output from a failed dump (auth errors)."""
    return """[usb|script] pm3 --> hf mf dump
[+] Reading sector access bits...
[-] Auth error on block 4
[-] Dump failed"""
