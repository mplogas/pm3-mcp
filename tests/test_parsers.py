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
    parse_autopwn,
    parse_darkside,
    parse_hardnested,
    parse_chk_keys,
    sector_to_trailer,
    parse_desfire_info,
    parse_desfire_apps,
    parse_detect_tag,
    parse_desfire_files,
    parse_trace_list,
    parse_hw_trace_status,
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

    def test_removes_bracketed_spinner_characters(self):
        text = "[\\]loading...[|]still going...[/]done"
        result = strip_ansi(text)
        assert "[\\]" not in result
        assert "[|]" not in result
        assert "[/]" not in result
        assert "loading" in result
        assert "done" in result

    def test_preserves_bare_pipe_in_tables(self):
        text = "[=]   0 | AD 6F EF EC | .o.."
        result = strip_ansi(text)
        assert "|" in result

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
        assert result["hex"] == "AD 6F EF EC C1 08 04 00 62 63 64 65 66 67 68 69"

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


# ---------------------------------------------------------------------------
# sector_to_trailer
# ---------------------------------------------------------------------------

class TestSectorToTrailer:
    def test_sector_0(self):
        assert sector_to_trailer(0) == 3

    def test_sector_1(self):
        assert sector_to_trailer(1) == 7

    def test_sector_15(self):
        assert sector_to_trailer(15) == 63

    def test_sector_5(self):
        assert sector_to_trailer(5) == 23


# ---------------------------------------------------------------------------
# parse_autopwn
# ---------------------------------------------------------------------------

class TestParseAutopwn:
    def test_all_default_complete(self, autopwn_all_default_output):
        result = parse_autopwn(autopwn_all_default_output)
        assert result["complete"] is True
        assert len(result["keys"]) == 16

    def test_all_default_methods(self, autopwn_all_default_output):
        result = parse_autopwn(autopwn_all_default_output)
        for entry in result["keys"]:
            assert entry["method_a"] == "D"
            assert entry["method_b"] == "D"

    def test_all_default_key_values(self, autopwn_all_default_output):
        result = parse_autopwn(autopwn_all_default_output)
        for entry in result["keys"]:
            assert entry["key_a"] == "FFFFFFFFFFFF"
            assert entry["key_b"] == "FFFFFFFFFFFF"

    def test_hardnested_mixed_keys(self, autopwn_hardnested_output):
        result = parse_autopwn(autopwn_hardnested_output)
        assert result["complete"] is True
        # Sector 1 was hardnested
        s1 = next(k for k in result["keys"] if k["sector"] == 1)
        assert s1["key_a"] == "4D57414C5648"
        assert s1["method_a"] == "H"

    def test_execution_time(self, autopwn_all_default_output):
        result = parse_autopwn(autopwn_all_default_output)
        assert result["execution_time_s"] == 2

    def test_dump_files(self, autopwn_all_default_output):
        result = parse_autopwn(autopwn_all_default_output)
        assert any("dump.bin" in f for f in result["dump_files"])
        assert any("dump.json" in f for f in result["dump_files"])
        assert any("key.bin" in f for f in result["dump_files"])


# ---------------------------------------------------------------------------
# parse_darkside
# ---------------------------------------------------------------------------

class TestParseDarkside:
    def test_success(self, darkside_success_output):
        result = parse_darkside(darkside_success_output)
        assert result["success"] is True
        assert result["key"] == "A0A1A2A3A4A5"

    def test_failure(self, darkside_fail_output):
        result = parse_darkside(darkside_fail_output)
        assert result["success"] is False
        assert "not vulnerable" in result["error"].lower() or "prng" in result["error"].lower()


# ---------------------------------------------------------------------------
# parse_hardnested
# ---------------------------------------------------------------------------

class TestParseHardnested:
    def test_success(self, hardnested_success_output):
        result = parse_hardnested(hardnested_success_output)
        assert result["success"] is True
        assert result["key"] == "4D57414C5648"

    def test_has_target_info(self, hardnested_success_output):
        result = parse_hardnested(hardnested_success_output)
        assert result["target_sector"] == 1


# ---------------------------------------------------------------------------
# parse_chk_keys
# ---------------------------------------------------------------------------

class TestParseChkKeys:
    def test_found_count(self, chk_keys_output):
        result = parse_chk_keys(chk_keys_output)
        assert result["found_count"] == 6  # sectors 0,2,3 have both A+B

    def test_missing_keys(self, chk_keys_output):
        result = parse_chk_keys(chk_keys_output)
        s1 = next(k for k in result["keys"] if k["sector"] == 1)
        assert s1["key_a"] is None
        assert s1["key_b"] is None

    def test_found_keys(self, chk_keys_output):
        result = parse_chk_keys(chk_keys_output)
        s0 = next(k for k in result["keys"] if k["sector"] == 0)
        assert s0["key_a"] == "FFFFFFFFFFFF"
        assert s0["key_b"] == "FFFFFFFFFFFF"


# ---------------------------------------------------------------------------
# parse_autopwn edge cases
# ---------------------------------------------------------------------------

class TestParseAutopwnNoTag:
    def test_no_tag_returns_error(self, autopwn_no_tag_output):
        result = parse_autopwn(autopwn_no_tag_output)
        assert result["complete"] is False
        assert result["error"] is not None
        assert "No tag" in result["error"]
        assert result["keys"] == []

    def test_no_tag_has_zero_keys(self, autopwn_no_tag_output):
        result = parse_autopwn(autopwn_no_tag_output)
        assert len(result["keys"]) == 0


class TestParseAutopwnPartialNoTable:
    def test_extracts_keys_from_individual_lines(self, autopwn_partial_no_table_output):
        result = parse_autopwn(autopwn_partial_no_table_output)
        assert len(result["keys"]) == 3  # sectors 0, 2, 3

    def test_sector_0_keys(self, autopwn_partial_no_table_output):
        result = parse_autopwn(autopwn_partial_no_table_output)
        s0 = next(k for k in result["keys"] if k["sector"] == 0)
        assert s0["key_a"] == "FFFFFFFFFFFF"
        assert s0["key_b"] == "FFFFFFFFFFFF"

    def test_not_complete(self, autopwn_partial_no_table_output):
        result = parse_autopwn(autopwn_partial_no_table_output)
        assert result["complete"] is False

    def test_has_hardnested_error(self, autopwn_partial_no_table_output):
        result = parse_autopwn(autopwn_partial_no_table_output)
        assert result["error"] is not None
        assert "First_Byte_Sum" in result["error"] or "hardnested" in result["error"].lower()

    def test_existing_all_default_still_works(self, autopwn_all_default_output):
        """Make sure the existing summary table parsing still works."""
        result = parse_autopwn(autopwn_all_default_output)
        assert result["complete"] is True
        assert len(result["keys"]) == 16
        assert result["error"] is None


# ---------------------------------------------------------------------------
# DESFire parsers
# ---------------------------------------------------------------------------

class TestParseDesfireInfo:
    def test_found(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["found"] is True

    def test_uid(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["uid"] == "04406C62241290"

    def test_production(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert "2022" in result["production"]

    def test_hw_version(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert "EV2" in result["hw_version"]

    def test_storage(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["storage_bytes"] == 8192

    def test_free_memory(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["free_bytes"] == 3328

    def test_signature(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["signature_ok"] is True

    def test_app_count(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["app_count"] == 2

    def test_key_type(self, desfire_info_output):
        result = parse_desfire_info(desfire_info_output)
        assert result["key_type"] == "AES"

    def test_no_tag(self, desfire_info_no_tag_output):
        result = parse_desfire_info(desfire_info_no_tag_output)
        assert result["found"] is False
        assert "error" in result
        assert result["error"] is not None


class TestParseDesfireApps:
    def test_app_count(self, desfire_lsapp_output):
        result = parse_desfire_apps(desfire_lsapp_output)
        assert result["app_count"] == 2

    def test_app_ids(self, desfire_lsapp_output):
        result = parse_desfire_apps(desfire_lsapp_output)
        aids = [a["aid"] for a in result["apps"]]
        assert "357" in aids or "0357" in aids

    def test_app_description(self, desfire_lsapp_output):
        result = parse_desfire_apps(desfire_lsapp_output)
        descs = [a.get("description", "") or "" for a in result["apps"]]
        assert any("LEGIC" in d for d in descs)

    def test_app_auth_methods(self, desfire_lsapp_output):
        result = parse_desfire_apps(desfire_lsapp_output)
        assert len(result["apps"]) >= 1
        first_app = result["apps"][0]
        assert "auth_methods" in first_app
        assert isinstance(first_app["auth_methods"], dict)


class TestParseDesfireFiles:
    def test_auth_required(self, desfire_lsfiles_auth_required_output):
        result = parse_desfire_files(desfire_lsfiles_auth_required_output)
        assert result["success"] is False
        assert "auth" in result["error"].lower()


# ---------------------------------------------------------------------------
# parse_detect_tag (smart routing)
# ---------------------------------------------------------------------------

class TestParseDetectTag:
    def test_mifare_classic(self, auto_mifare_classic_output):
        result = parse_detect_tag(auto_mifare_classic_output)
        assert result["found"] is True
        assert result["frequency"] == "hf"
        assert result["protocol"] == "mifare_classic"
        assert result["tag_type"] == "MIFARE Classic 1K"
        assert result["uid"] == "AD6FEFEC"
        assert result["details"]["prng"] == "weak"
        assert "autopwn" in result["suggested_tools"]

    def test_mifare_classic_static_nonce(self, auto_mifare_classic_output):
        result = parse_detect_tag(auto_mifare_classic_output)
        assert result["details"].get("static_nonce") is True

    def test_desfire(self, auto_desfire_output):
        result = parse_detect_tag(auto_desfire_output)
        assert result["found"] is True
        assert result["frequency"] == "hf"
        assert result["protocol"] == "mifare_desfire"
        assert result["tag_type"] == "MIFARE DESFire EV2"
        assert result["uid"] == "04406C62241290"
        assert "desfire_info" in result["suggested_tools"]

    def test_hid_prox(self, auto_hid_prox_output):
        result = parse_detect_tag(auto_hid_prox_output)
        assert result["found"] is True
        assert result["frequency"] == "lf"
        assert result["protocol"] == "hid_prox"
        assert result["details"]["facility_code"] == 150
        assert result["details"]["card_number"] == 20182

    def test_em410x(self, auto_em410x_output):
        result = parse_detect_tag(auto_em410x_output)
        assert result["found"] is True
        assert result["frequency"] == "lf"
        assert result["protocol"] == "em410x"
        assert result["uid"] == "EA002B1E14"

    def test_iso15693(self, auto_iso15693_output):
        result = parse_detect_tag(auto_iso15693_output)
        assert result["found"] is True
        assert result["frequency"] == "hf"
        assert result["protocol"] == "iso15693"
        assert "NXP" in result["tag_type"]

    def test_no_tag(self, auto_no_tag_output):
        result = parse_detect_tag(auto_no_tag_output)
        assert result["found"] is False
        assert result["protocol"] is None
        assert result["suggested_tools"] == []


# ---------------------------------------------------------------------------
# parse_trace_list
# ---------------------------------------------------------------------------

class TestParseTraceList:
    def test_extracts_exchanges(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        assert len(result["exchanges"]) > 0

    def test_exchange_fields(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        ex = result["exchanges"][0]
        assert "src" in ex
        assert ex["src"] in ("Rdr", "Tag")
        assert "data_hex" in ex
        assert "annotation" in ex

    def test_reader_and_tag_present(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        sources = {e["src"] for e in result["exchanges"]}
        assert "Rdr" in sources
        assert "Tag" in sources

    def test_exchange_count(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        assert result["exchange_count"] == len(result["exchanges"])

    def test_trace_bytes(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        assert result["trace_bytes"] == 741

    def test_crc_field(self, trace_list_iso15693_output):
        result = parse_trace_list(trace_list_iso15693_output)
        crcs = [e.get("crc") for e in result["exchanges"]]
        assert "ok" in crcs or "!!" in crcs

    def test_14a_auth_nonces(self, trace_list_14a_auth_output):
        result = parse_trace_list(trace_list_14a_auth_output)
        assert len(result["auth_nonces"]) > 0
        nonce = result["auth_nonces"][0]
        assert "nt" in nonce
        assert "nr_ar" in nonce

    def test_empty_trace(self, trace_list_empty_output):
        result = parse_trace_list(trace_list_empty_output)
        assert result["exchanges"] == []
        assert result["exchange_count"] == 0


# ---------------------------------------------------------------------------
# parse_hw_trace_status
# ---------------------------------------------------------------------------

class TestParseHwTraceStatus:
    def test_trace_present(self, hw_status_with_trace_output):
        result = parse_hw_trace_status(hw_status_with_trace_output)
        assert result["trace_len"] == 741

    def test_no_trace(self, hw_status_no_trace_output):
        result = parse_hw_trace_status(hw_status_no_trace_output)
        assert result["trace_len"] == 0
