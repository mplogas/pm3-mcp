"""Tests for pm3_mcp.parsers -- pure text-in, dict-out functions.

All fixtures are defined in conftest.py and represent real or simulated
Proxmark3 iceman firmware output.
"""

import pytest
from pm3_mcp.parsers import (
    strip_ansi,
    parse_hw_status,
    parse_hf_search,
    parse_lf_search,
    parse_hf_14a_info,
    parse_block_read,
    parse_dump_result,
)


# ---------------------------------------------------------------------------
# strip_ansi
# ---------------------------------------------------------------------------

class TestStripAnsi:
    def test_removes_color_codes(self):
        text = "\x1b[31mred\x1b[0m normal"
        assert strip_ansi(text) == "red normal"

    def test_removes_bold_codes(self):
        text = "\x1b[1mBold\x1b[22m text"
        assert strip_ansi(text) == "Bold text"

    def test_removes_256_color_codes(self):
        text = "\x1b[38;5;200mcolor\x1b[0m"
        assert strip_ansi(text) == "color"

    def test_removes_spinner_characters(self):
        text = "loading \\ done"
        result = strip_ansi(text)
        assert "\\" not in result

    def test_removes_all_spinner_chars(self):
        for ch in ["|", "/", "\\"]:
            assert ch not in strip_ansi(ch)

    def test_preserves_plain_text(self):
        text = "plain text with numbers 123 and punctuation: [+] ok"
        assert strip_ansi(text) == text

    def test_empty_string(self):
        assert strip_ansi("") == ""

    def test_multiple_codes(self):
        text = "\x1b[32m\x1b[1mGreen bold\x1b[0m\x1b[0m"
        assert strip_ansi(text) == "Green bold"


# ---------------------------------------------------------------------------
# parse_hw_status
# ---------------------------------------------------------------------------

class TestParseHwStatus:
    def test_fpga_image(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert "fpga_image" in result
        assert "fpga_pm3_lf" in result["fpga_image"]

    def test_flash_memory_kb(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert result["flash_memory_kb"] == 2048

    def test_unique_id(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert result["unique_id"] == "0x0B33383153325041"

    def test_dict_mifare_count(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        dicts = result["dictionaries"]
        assert dicts["mifare"] == 2375

    def test_dict_t55xx_count(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        dicts = result["dictionaries"]
        assert dicts["t55xx"] == 125

    def test_dict_iclass_count(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        dicts = result["dictionaries"]
        assert dicts["iclass"] == 29

    def test_standalone_mode(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert "standalone_mode" in result
        assert "SamyRun" in result["standalone_mode"] or "HID26" in result["standalone_mode"]

    def test_transfer_speed_bps(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert result["transfer_speed_bps"] == 502784

    def test_returns_dict(self, hw_status_output):
        result = parse_hw_status(hw_status_output)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# parse_hf_search
# ---------------------------------------------------------------------------

class TestParseHfSearch:
    def test_no_tag_found_is_false(self, hf_search_no_tag_output):
        result = parse_hf_search(hf_search_no_tag_output)
        assert result["found"] is False

    def test_no_tag_uid_is_none(self, hf_search_no_tag_output):
        result = parse_hf_search(hf_search_no_tag_output)
        assert result.get("uid") is None

    def test_no_tag_tag_type_is_none(self, hf_search_no_tag_output):
        result = parse_hf_search(hf_search_no_tag_output)
        assert result.get("tag_type") is None

    def test_no_tag_has_raw(self, hf_search_no_tag_output):
        result = parse_hf_search(hf_search_no_tag_output)
        assert "raw" in result
        assert len(result["raw"]) > 0

    def test_tag_found_is_true(self, hf_search_found_output):
        result = parse_hf_search(hf_search_found_output)
        assert result["found"] is True

    def test_tag_found_uid(self, hf_search_found_output):
        result = parse_hf_search(hf_search_found_output)
        assert result["uid"] is not None
        assert len(result["uid"]) > 0

    def test_tag_found_tag_type(self, hf_search_found_output):
        result = parse_hf_search(hf_search_found_output)
        assert result["tag_type"] is not None


# ---------------------------------------------------------------------------
# parse_lf_search
# ---------------------------------------------------------------------------

class TestParseLfSearch:
    def test_no_tag_found_is_false(self, lf_search_no_tag_output):
        result = parse_lf_search(lf_search_no_tag_output)
        assert result["found"] is False

    def test_no_tag_tag_type_is_none(self, lf_search_no_tag_output):
        result = parse_lf_search(lf_search_no_tag_output)
        assert result.get("tag_type") is None

    def test_no_tag_tag_id_is_none(self, lf_search_no_tag_output):
        result = parse_lf_search(lf_search_no_tag_output)
        assert result.get("tag_id") is None

    def test_no_tag_has_raw(self, lf_search_no_tag_output):
        result = parse_lf_search(lf_search_no_tag_output)
        assert "raw" in result

    def test_em410x_found_is_true(self, lf_search_em410x_output):
        result = parse_lf_search(lf_search_em410x_output)
        assert result["found"] is True

    def test_em410x_tag_type(self, lf_search_em410x_output):
        result = parse_lf_search(lf_search_em410x_output)
        assert result["tag_type"] == "EM410x"

    def test_em410x_tag_id(self, lf_search_em410x_output):
        result = parse_lf_search(lf_search_em410x_output)
        assert result["tag_id"] is not None
        assert len(result["tag_id"]) > 0


# ---------------------------------------------------------------------------
# parse_hf_14a_info
# ---------------------------------------------------------------------------

class TestParseHf14aInfo:
    def test_uid(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert result["uid"] == "04A3B2C1"

    def test_atqa(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert result["atqa"] == "0004"

    def test_sak(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert result["sak"] == "08"

    def test_possible_types_is_list(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert isinstance(result["possible_types"], list)

    def test_possible_types_contains_mifare_classic(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert any("MIFARE Classic 1K" in t for t in result["possible_types"])

    def test_prng(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert result["prng"] == "weak"

    def test_magic(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert "Gen 1a" in result["magic"]

    def test_has_raw(self, hf_14a_info_output):
        result = parse_hf_14a_info(hf_14a_info_output)
        assert "raw" in result
        assert len(result["raw"]) > 0


# ---------------------------------------------------------------------------
# parse_block_read
# ---------------------------------------------------------------------------

class TestParseBlockRead:
    def test_success_true(self, hf_mf_rdbl_output):
        result = parse_block_read(hf_mf_rdbl_output)
        assert result["success"] is True

    def test_block_number(self, hf_mf_rdbl_output):
        result = parse_block_read(hf_mf_rdbl_output)
        assert result["block"] == 0

    def test_hex_data(self, hf_mf_rdbl_output):
        result = parse_block_read(hf_mf_rdbl_output)
        # space-separated hex bytes
        assert result["hex"] == "04 A3 B2 C1 D4 08 04 00 62 63 64 65 66 67 68 69"

    def test_bytes_count(self, hf_mf_rdbl_output):
        result = parse_block_read(hf_mf_rdbl_output)
        assert result["bytes"] == 16

    def test_ascii_present(self, hf_mf_rdbl_output):
        result = parse_block_read(hf_mf_rdbl_output)
        assert "ascii" in result

    def test_auth_fail_success_false(self, hf_mf_rdbl_auth_fail_output):
        result = parse_block_read(hf_mf_rdbl_auth_fail_output)
        assert result["success"] is False

    def test_auth_fail_error_message(self, hf_mf_rdbl_auth_fail_output):
        result = parse_block_read(hf_mf_rdbl_auth_fail_output)
        assert "error" in result
        assert len(result["error"]) > 0

    def test_auth_fail_block_number(self, hf_mf_rdbl_auth_fail_output):
        result = parse_block_read(hf_mf_rdbl_auth_fail_output)
        assert result["block"] == 4


# ---------------------------------------------------------------------------
# parse_dump_result
# ---------------------------------------------------------------------------

class TestParseDumpResult:
    def test_success_true(self, dump_success_output, tmp_path):
        dump_path = str(tmp_path)
        result = parse_dump_result(dump_success_output, dump_path)
        assert result["success"] is True

    def test_dump_path_preserved(self, dump_success_output, tmp_path):
        dump_path = str(tmp_path)
        result = parse_dump_result(dump_success_output, dump_path)
        assert result["dump_path"] == dump_path

    def test_output_file_present(self, dump_success_output, tmp_path):
        dump_path = str(tmp_path)
        result = parse_dump_result(dump_success_output, dump_path)
        assert "output_file" in result
        assert result["output_file"] is not None

    def test_has_raw(self, dump_success_output, tmp_path):
        dump_path = str(tmp_path)
        result = parse_dump_result(dump_success_output, dump_path)
        assert "raw" in result

    def test_failure_success_false(self, dump_fail_output, tmp_path):
        dump_path = str(tmp_path)
        result = parse_dump_result(dump_fail_output, dump_path)
        assert result["success"] is False
