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
    """Real output from 'pm3 -c hf mf rdbl --blk 0' (table format)."""
    return """[usb|script] pm3 --> hf mf rdbl --blk 0 -k FFFFFFFFFFFF -a

[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | AD 6F EF EC C1 08 04 00 62 63 64 65 66 67 68 69 | .o......bcdefghi"""


@pytest.fixture
def hf_mf_rdbl_auth_fail_output():
    """Simulated output from failed auth on block read."""
    return """[usb|script] pm3 --> hf mf rdbl --blk 4 -k FFFFFFFFFFFF -a
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


@pytest.fixture
def autopwn_all_default_output():
    """Real output from autopwn on a card with all default keys (4s)."""
    return """[usb|script] pm3 --> hf mf autopwn -f /tmp/artifacts/dump

[!] Known key failed. Can't authenticate to block   0 key type A
[!] No known key was supplied, key recovery might fail
[+] loaded 5 user keys
[+] loaded 61 hardcoded keys
[=] Running strategy 1
[+] Target sector   0 key type A -- found valid key [ FFFFFFFFFFFF ] (used for nested / hardnested attack)
[+] Target sector   0 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   1 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   1 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   4 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   4 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   5 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   5 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   6 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   6 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   7 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   7 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   8 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   8 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   9 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   9 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  10 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  10 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  11 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  11 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  12 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  12 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  13 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  13 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  14 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  14 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  15 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  15 key type B -- found valid key [ FFFFFFFFFFFF ]

[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  001 | 007 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  002 | 011 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  003 | 015 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  004 | 019 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  005 | 023 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  006 | 027 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  007 | 031 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  008 | 035 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  009 | 039 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  010 | 043 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  011 | 047 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  012 | 051 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  013 | 055 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  014 | 059 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  015 | 063 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+] -----+-----+--------------+---+--------------+----
[=] ( D:Dictionary / S:darkSide / U:User / R:Reused / N:Nested / H:Hardnested / C:statiCnested / A:keyA  )

[+] Generating binary key file
[+] Found keys have been dumped to `/tmp/artifacts/dump-key.bin`
[=] Transferring keys to simulator memory ( ok )
[=] Dumping card content to emulator memory (Cmd Error: 04 can occur)
[=] downloading card content from emulator memory
[+] Saved 1024 bytes to binary file `/tmp/artifacts/dump.bin`
[+] Saved to json file /tmp/artifacts/dump.json
[=] Autopwn execution time: 2 seconds"""


@pytest.fixture
def autopwn_hardnested_output():
    """Real output from autopwn with hardnested attack on sectors 1/4/5."""
    return """[usb|script] pm3 --> hf mf autopwn -f /tmp/artifacts/dump

[+] Target sector   0 key type A -- found valid key [ FFFFFFFFFFFF ] (used for nested / hardnested attack)
[+] Target sector   0 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   6 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   6 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   7 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   7 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   8 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   8 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   9 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   9 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  10 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  10 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  11 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  11 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  12 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  12 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  13 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  13 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  14 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  14 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  15 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector  15 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   1 key type A -- found valid key [ 4D57414C5648 ]
[+] Target sector   4 key type A -- found valid key [ 4D57414C5648 ]
[+] Target sector   5 key type A -- found valid key [ 4D57414C5648 ]
[+] Target sector   1 key type B -- found valid key [ 4D48414C5648 ]
[+] Target sector   4 key type B -- found valid key [ 4D48414C5648 ]
[+] Target sector   5 key type B -- found valid key [ 4D48414C5648 ]

[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  001 | 007 | 4D57414C5648 | H | 4D48414C5648 | H
[+]  002 | 011 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  003 | 015 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  004 | 019 | 4D57414C5648 | R | 4D48414C5648 | R
[+]  005 | 023 | 4D57414C5648 | R | 4D48414C5648 | R
[+]  006 | 027 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  007 | 031 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  008 | 035 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  009 | 039 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  010 | 043 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  011 | 047 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  012 | 051 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  013 | 055 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  014 | 059 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+]  015 | 063 | FFFFFFFFFFFF | D | FFFFFFFFFFFF | D
[+] -----+-----+--------------+---+--------------+----
[=] ( D:Dictionary / S:darkSide / U:User / R:Reused / N:Nested / H:Hardnested / C:statiCnested / A:keyA  )

[+] Generating binary key file
[+] Found keys have been dumped to `/tmp/artifacts/dump-key.bin`
[=] Transferring keys to simulator memory ( ok )
[=] Dumping card content to emulator memory (Cmd Error: 04 can occur)
[=] downloading card content from emulator memory
[+] Saved 1024 bytes to binary file `/tmp/artifacts/dump.bin`
[+] Saved to json file /tmp/artifacts/dump.json
[=] Autopwn execution time: 73 seconds"""


@pytest.fixture
def darkside_success_output():
    """Simulated output from successful darkside attack."""
    return """[usb|script] pm3 --> hf mf darkside
[=] Darkside attack running...
[+] Found valid key: A0A1A2A3A4A5"""


@pytest.fixture
def darkside_fail_output():
    """Simulated output from failed darkside attack (hard PRNG)."""
    return """[usb|script] pm3 --> hf mf darkside
[-] Card is not vulnerable to Darkside attack (its PRNG is not predictable)"""


@pytest.fixture
def hardnested_success_output():
    """Simulated output from successful hardnested attack."""
    return """[usb|script] pm3 --> hf mf hardnested --blk 3 -a -k FFFFFFFFFFFF --tblk 7 --ta
[=] ---------+---------+---------------------------------------------------------+-----------------+-------
[=]        0 |       0 | Start using 4 threads and NEON SIMD core                |                 |
[=]        0 |       0 | Brute force benchmark: 223 million (2^27.7) keys/s      | 140737488355328 |    7d
[=]       38 |    2963 | Brute force phase completed.  Key found: 4D57414C5648 |               0 |    0s
[=] ---------+---------+---------------------------------------------------------+-----------------+-------
[+] Target sector   1 key type A -- found valid key [ 4D57414C5648 ]"""


@pytest.fixture
def chk_keys_output():
    """Simulated output from hf mf chk."""
    return """[usb|script] pm3 --> hf mf chk --1k
[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  001 | 007 | ------------ | 0 | ------------ | 0
[+]  002 | 011 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  003 | 015 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+] -----+-----+--------------+---+--------------+----
[+] ( 0:Failed / 1:Success )"""


@pytest.fixture
def autopwn_no_tag_output():
    """Real output from autopwn with no tag on reader."""
    return """[usb|script] pm3 --> hf mf autopwn
[-] No tag detected or other tag communication error
[?] Hint: Try some distance or position of the card"""


@pytest.fixture
def autopwn_partial_no_table_output():
    """Real output from autopwn that found some keys but failed hardnested.

    No summary table printed. Only individual key recovery lines.
    """
    return """[usb|script] pm3 --> hf mf autopwn

[!] Known key failed. Can't authenticate to block   0 key type A
[+] loaded 5 user keys
[+] loaded 61 hardcoded keys
[=] Running strategy 1
[=] .
[=] Running strategy 2
[=] .
[+] Target sector   0 key type A -- found valid key [ FFFFFFFFFFFF ] (used for nested / hardnested attack)
[+] Target sector   0 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   2 key type B -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type A -- found valid key [ FFFFFFFFFFFF ]
[+] Target sector   3 key type B -- found valid key [ FFFFFFFFFFFF ]
[#] AcquireEncryptedNonces: Auth1 error
[#] AcquireEncryptedNonces: Auth1 error
[-] No match for the First_Byte_Sum (130), is the card a genuine MFC Ev1?"""


@pytest.fixture
def desfire_info_output():
    """Real output from 'hf mfdes info' on a DESFire EV2 8K card."""
    return """[usb|script] pm3 --> hf mfdes info

[=] ---------------------------------- Tag Information ----------------------------------
[+]               UID: 04 40 6C 62 24 12 90
[+]      Batch number: CF 6D D6 61 31
[+]   Production date: week 18 / 2022
[+]      Product type: MIFARE DESFire native IC (physical card)

[=] --- Hardware Information
[=]    raw: 04010112001A05
[=]      Vendor Id: NXP Semiconductors Germany
[=]           Type: 0x01 ( DESFire )
[=]        Subtype: 0x01
[=]        Version: 12.0 ( DESFire EV2 )
[=]   Storage size: 0x1A ( 8192 bytes )
[=]       Protocol: 0x05 ( ISO 14443-2, 14443-3 )

[=] --- Software Information
[=]    raw: 04010102011A05
[=]      Vendor Id: NXP Semiconductors Germany
[=]           Type: 0x01 ( DESFire )
[=]        Subtype: 0x01
[=]        Version: 2.1
[=]   Storage size: 0x1A ( 8192 bytes )
[=]       Protocol: 0x05 ( ISO 14443-3, 14443-4 )

[=] --------------------------------- Card capabilities ---------------------------------

[=] --- Tag Signature
[=]  IC signature public key name: NTAG424DNA, NTAG424DNATT, DESFire EV2, DESFire Light EV2
[+]        Signature verification: successful

[+] --- AID list ( 2 found )
[+] 000357,
[+] 0000F0,

[+] ------------------------------------ PICC level -------------------------------------
[+] # applications....... 2
[+] PICC level auth commands
[+]    Auth AES.......... YES
[+]    Auth Ev2.......... YES
[+] Key type... AES
[+] Key cnt.... 1
[+] PICC key 0 version: 0 (0x00)

[=] --- Free memory
[+]    Available free memory on card... 3328 bytes

[=] Standalone DESFire"""


@pytest.fixture
def desfire_info_no_tag_output():
    """Output from 'hf mfdes info' with no tag present."""
    return """[usb|script] pm3 --> hf mfdes info
[#] Can't select card
[!] Can't select card"""


@pytest.fixture
def desfire_lsapp_output():
    """Real output from 'hf mfdes lsapp --no-auth' on a DESFire EV2."""
    return """[usb|script] pm3 --> hf mfdes lsapp --no-auth
[=] It may take up to 15 seconds. Processing...

[+] ------------------------------------ PICC level -------------------------------------
[+] # applications....... 2

[+] --------------------------------- Applications list ---------------------------------
[+] Application ID....... 0x357
[+]    ISO id............ 0x0000
[=]   DF AID Function... 000357  : LEGIC [LEGIC]
[+] Auth commands
[+]    Auth.............. YES
[+]    Auth ISO.......... YES
[+]    Auth AES.......... NO

[+] Application ID....... 0xF0
[+]    ISO id............ 0x0000
[=]   DF AID Function... 0000F0  : OMNY (One Metro New York) (JFK) / BMW Digital Key [Metropolitan Transportation Authority (MTA) / Bayerische Motoren Werke (BMW) AG]
[+] Auth commands
[+]    Auth.............. NO
[+]    Auth AES.......... YES
[+]    Auth Ev2.......... YES"""


@pytest.fixture
def desfire_lsfiles_auth_required_output():
    """Output from 'hf mfdes lsfiles' when auth is required."""
    return """[usb|script] pm3 --> hf mfdes lsfiles --no-auth --aid 000357
[!!] Desfire GetFileIDList command error. Result: -20"""


@pytest.fixture
def auto_mifare_classic_output():
    """Real auto output detecting a MIFARE Classic 1K with weak PRNG."""
    return """[usb|script] pm3 --> auto
[=] lf search
[=] Couldn't identify a chipset
[=] hf search
[+]  UID: AD 6F EF EC   ( ONUID, re-used )
[+] ATQA: 00 04
[+]  SAK: 08 [2]
[+] Possible types:
[+]    MIFARE Classic 1K
[+] Prng detection..... weak
[+] Static nonce....... yes
[+] Valid ISO 14443-A tag found"""


@pytest.fixture
def auto_desfire_output():
    """Real auto output detecting a DESFire EV2."""
    return """[usb|script] pm3 --> auto
[=] lf search
[=] Couldn't identify a chipset
[=] hf search
[+]  UID: 04 40 6C 62 24 12 90   ( double )
[+] ATQA: 03 44
[+]  SAK: 20 [1]
[+] Possible types:
[+]    MIFARE DESFire EV2
[+] ATS: 06 75 77 81 02 80 [ 02 F0 ]
[+] Valid ISO 14443-A tag found"""


@pytest.fixture
def auto_hid_prox_output():
    """Real auto output detecting an HID Prox LF tag."""
    return """[usb|script] pm3 --> auto
[=] lf search
[+] [H10301  ] HID H10301 26-bit                FC: 150  CN: 20182  parity ( ok )
[=] raw: 0000000000000020072c9dad
[+] Valid HID Prox ID found!"""


@pytest.fixture
def auto_em410x_output():
    """Real auto output detecting an EM410x LF tag."""
    return """[usb|script] pm3 --> auto
[=] lf search
[+] EM 410x ID EA002B1E14
[+] EM410x ( RF/64 )
[+] Valid EM410x ID found!"""


@pytest.fixture
def auto_iso15693_output():
    """Real auto output detecting an ISO 15693 tag."""
    return """[usb|script] pm3 --> auto
[=] lf search
[=] Couldn't identify a chipset
[=] hf search
[+] UID.... E0 04 01 00 6A DB 10 F8
[+] TYPE MATCH NXP (Philips); IC SL2 ICS20/ICS21 ( SLI )
[+] Valid ISO 15693 tag found"""


@pytest.fixture
def auto_no_tag_output():
    """Real auto output with no tag present."""
    return """[usb|script] pm3 --> auto
[=] lf search
[=] Couldn't identify a chipset
[=] hf search
[!] No known/supported 13.56 MHz tags found"""


@pytest.fixture
def trace_list_iso15693_output():
    """Real decoded trace output from ISO 15693 sniff (captured 2026-03-26)."""
    return """[+] Recorded activity ( 741 bytes )
[=] start = start of start frame. end = end of frame. src = source of transfer.
[=] ISO15693 / iCLASS - all times are in carrier periods (1/13.56MHz)

      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation
------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------
          0 |      17920 | Rdr |02  E4  00  44                                                           |  !! | Proprietary IC MFG dependent
      35552 |     109280 | Tag |00  0F  F8  10  DB  6A  00  01  04  E0  00  00  1B  03  01  B9  8A       |  ok |
     107456 |     137664 | Rdr |02  20  00  47  EC  06  44                                               |  !! | READBLOCK(0)
     143776 |     176544 | Tag |00  00  00  00  00  77  CF                                               |  ok |
     442400 |     460320 | Rdr |02  E4  02  44                                                           |  !! | Proprietary IC MFG dependent
     685888 |     707904 | Rdr |02  20  0A  1D  FF                                                       |  ok | READBLOCK(10)
     712352 |     745120 | Tag |00  00  00  00  00  77  CF                                               |  ok |"""


@pytest.fixture
def trace_list_14a_auth_output():
    """Simulated decoded trace for MIFARE Classic authentication exchange."""
    return """[+] Recorded activity ( 256 bytes )
[=] start = start of start frame. end = end of frame. src = source of transfer.
[=] ISO14443-A - all times are in carrier periods (1/13.56MHz)

      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation
------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------
          0 |        992 | Rdr |26                                                                       |     | REQA
       2228 |       4596 | Tag |04  00                                                                   |     | ATQA
       7040 |       9504 | Rdr |93  20                                                                   |     | ANTICOLL
      11612 |      18412 | Tag |AD  6F  EF  EC  97                                                       |     | UID BCC
      20000 |      30000 | Rdr |60  00  F5  7B                                                           |  ok | AUTH-A(0)
      32000 |      36000 | Tag |AB  CD  12  34                                                           |     | TAG NONCE
      38000 |      46000 | Rdr |01  02  03  04  05  06  07  08                                           |     | NR AR (encrypted)
      48000 |      52000 | Tag |09  0A  0B  0C                                                           |     | AT (encrypted)"""


@pytest.fixture
def trace_list_empty_output():
    """Output when trace buffer is empty."""
    return """[-] You requested a trace list but there is no trace.
[-] Consider using `trace load` or removing parameter `-1`"""


@pytest.fixture
def hw_status_with_trace_output():
    """hw status output with traceLen > 0."""
    return """[usb|script] pm3 --> hw status
[#] Memory
[#]   BigBuf_size............. 36948
[#]   Available memory........ 36948
[#] Tracing
[#]   tracing ................ 0
[#]   traceLen ............... 741"""


@pytest.fixture
def hw_status_no_trace_output():
    """hw status output with traceLen = 0."""
    return """[usb|script] pm3 --> hw status
[#] Tracing
[#]   tracing ................ 0
[#]   traceLen ............... 0"""
