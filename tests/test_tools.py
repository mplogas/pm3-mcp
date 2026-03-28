"""Tests for pm3_mcp.tools -- tool implementations.

All tests mock ConnectionManager. No PM3 hardware needed.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from pm3_mcp.connection import ConnectionManager
from pm3_mcp import tools


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager():
    """Return a MagicMock with ConnectionManager spec."""
    return MagicMock(spec=ConnectionManager)


def _run_ok(output: str) -> dict:
    return {"success": True, "output": output, "returncode": 0}


def _run_fail(output: str = "", error: str = "command failed") -> dict:
    return {"success": False, "output": output, "returncode": 1, "error": error}


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    @pytest.mark.asyncio
    async def test_connect_success(self):
        mgr = _make_manager()
        mgr.connect.return_value = "abc12345"
        mgr.get.return_value = {
            "port": "/dev/ttyACM0",
            "engagement_path": "/tmp/engagements/test",
        }

        result = await tools.tool_connect(mgr, "/dev/ttyACM0", "my-tag")

        assert result["session_id"] == "abc12345"
        assert result["port"] == "/dev/ttyACM0"
        assert "engagement_path" in result
        mgr.connect.assert_called_once_with("my-tag", port="/dev/ttyACM0", project_path=None)

    @pytest.mark.asyncio
    async def test_connect_returns_none(self):
        """manager.connect() returns None when PM3 is not found/responding."""
        mgr = _make_manager()
        mgr.connect.return_value = None

        result = await tools.tool_connect(mgr, "/dev/ttyACM0", "my-tag")

        assert "error" in result
        assert result["error"]

    @pytest.mark.asyncio
    async def test_connect_auto_detect(self):
        """Port=None triggers auto-detection inside manager."""
        mgr = _make_manager()
        mgr.connect.return_value = "def67890"
        mgr.get.return_value = {
            "port": "/dev/ttyACM1",
            "engagement_path": "/tmp/engagements/auto",
        }

        result = await tools.tool_connect(mgr, None, "auto-tag")

        assert result["session_id"] == "def67890"
        mgr.connect.assert_called_once_with("auto-tag", port=None, project_path=None)

    @pytest.mark.asyncio
    async def test_connect_exception_returns_error(self):
        mgr = _make_manager()
        mgr.connect.side_effect = Exception("USB exploded")

        result = await tools.tool_connect(mgr, "/dev/ttyACM0", "boom")

        assert "error" in result
        assert "USB exploded" in result["error"]


# ---------------------------------------------------------------------------
# TestDisconnect
# ---------------------------------------------------------------------------

class TestDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_success(self):
        mgr = _make_manager()
        mgr.disconnect.return_value = None

        result = await tools.tool_disconnect(mgr, "abc12345")

        assert result == {"disconnected": True}
        mgr.disconnect.assert_called_once_with("abc12345")

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_session(self):
        mgr = _make_manager()
        mgr.disconnect.side_effect = KeyError("nonexistent")

        result = await tools.tool_disconnect(mgr, "nonexistent")

        assert "error" in result
        assert "nonexistent" in result["error"]


# ---------------------------------------------------------------------------
# TestHwStatus
# ---------------------------------------------------------------------------

class TestHwStatus:
    @pytest.mark.asyncio
    async def test_hw_status_returns_parsed_dict(self, hw_status_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hw_status_output)

        result = await tools.tool_hw_status(mgr, "abc12345")

        # parsed output should have dict counts and other fields
        assert "dictionaries" in result
        assert isinstance(result["dictionaries"], dict)
        assert result["dictionaries"]["mifare"] == 2375

    @pytest.mark.asyncio
    async def test_hw_status_flash_and_uid(self, hw_status_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hw_status_output)

        result = await tools.tool_hw_status(mgr, "abc12345")

        assert result["flash_memory_kb"] == 2048
        assert result["unique_id"] == "0x0B33383153325041"

    @pytest.mark.asyncio
    async def test_hw_status_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_hw_status(mgr, "abc12345")

        assert "error" in result
        assert "abc12345" in result["error"]

    @pytest.mark.asyncio
    async def test_hw_status_command_failure(self):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_fail(error="timeout")

        result = await tools.tool_hw_status(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestDetectTag
# ---------------------------------------------------------------------------

class TestDetectTag:
    @pytest.mark.asyncio
    async def test_detect_tag_mifare_classic(self):
        output = "[+]  UID: AD 6F EF EC\n[+] Possible types:\n[+]    MIFARE Classic 1K\n[+] Prng detection..... weak"
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(output)

        result = await tools.tool_detect_tag(mgr, "abc12345")

        assert result["found"] is True
        assert result["protocol"] == "mifare_classic"
        assert result["uid"] == "AD6FEFEC"
        assert "autopwn" in result["suggested_tools"]
        mgr.run_command.assert_called_once_with("abc12345", "auto", timeout=45)

    @pytest.mark.asyncio
    async def test_detect_tag_no_tag(self):
        output = "[=] Couldn't identify a chipset\n[!] No known/supported 13.56 MHz tags found"
        mgr = _make_manager()
        mgr.run_command.return_value = {"success": False, "output": output, "returncode": 1}

        result = await tools.tool_detect_tag(mgr, "abc12345")

        assert result["found"] is False
        assert result["protocol"] is None

    @pytest.mark.asyncio
    async def test_detect_tag_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_detect_tag(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestHfInfo
# ---------------------------------------------------------------------------

class TestHfInfo:
    @pytest.mark.asyncio
    async def test_hf_info_found(self, hf_search_found_output, hf_14a_info_output):
        mgr = _make_manager()
        mgr.run_command.side_effect = [
            _run_ok(hf_search_found_output),
            _run_ok(hf_14a_info_output),
        ]

        result = await tools.tool_hf_info(mgr, "abc12345")

        assert result["found"] is True
        assert result["search"]["uid"] is not None
        assert result["info"] is not None
        assert result["info"]["uid"] == "04A3B2C1"

    @pytest.mark.asyncio
    async def test_hf_info_found_calls_both_commands(self, hf_search_found_output, hf_14a_info_output):
        mgr = _make_manager()
        mgr.run_command.side_effect = [
            _run_ok(hf_search_found_output),
            _run_ok(hf_14a_info_output),
        ]

        await tools.tool_hf_info(mgr, "abc12345")

        assert mgr.run_command.call_count == 2
        first_cmd = mgr.run_command.call_args_list[0][0][1]
        second_cmd = mgr.run_command.call_args_list[1][0][1]
        assert first_cmd == "hf search"
        assert second_cmd == "hf 14a info"

    @pytest.mark.asyncio
    async def test_hf_info_not_found(self, hf_search_no_tag_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_search_no_tag_output)

        result = await tools.tool_hf_info(mgr, "abc12345")

        assert result["found"] is False
        assert result["info"] is None
        # Should not call hf 14a info when no tag found
        assert mgr.run_command.call_count == 1

    @pytest.mark.asyncio
    async def test_hf_info_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_hf_info(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestLfInfo
# ---------------------------------------------------------------------------

class TestLfInfo:
    @pytest.mark.asyncio
    async def test_lf_info_not_found(self, lf_search_no_tag_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(lf_search_no_tag_output)

        result = await tools.tool_lf_info(mgr, "abc12345")

        assert result["found"] is False
        assert result["tag_type"] is None

    @pytest.mark.asyncio
    async def test_lf_info_em410x_found(self, lf_search_em410x_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(lf_search_em410x_output)

        result = await tools.tool_lf_info(mgr, "abc12345")

        assert result["found"] is True
        assert result["tag_type"] == "EM410x"

    @pytest.mark.asyncio
    async def test_lf_info_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_lf_info(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestReadBlock
# ---------------------------------------------------------------------------

class TestReadBlock:
    @pytest.mark.asyncio
    async def test_read_block_success(self, hf_mf_rdbl_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_mf_rdbl_output)

        result = await tools.tool_read_block(mgr, "abc12345", 0)

        assert result["success"] is True
        assert result["block"] == 0
        assert result["hex"] is not None
        assert result["bytes"] == 16

    @pytest.mark.asyncio
    async def test_read_block_uses_key_a_flag(self, hf_mf_rdbl_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_mf_rdbl_output)

        await tools.tool_read_block(mgr, "abc12345", 0, key="FFFFFFFFFFFF", key_type="A")

        cmd = mgr.run_command.call_args[0][1]
        assert " -a" in cmd
        assert " -b" not in cmd or "--blk" in cmd  # -b is key type B, --blk is block num

    @pytest.mark.asyncio
    async def test_read_block_uses_key_b_flag(self, hf_mf_rdbl_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_mf_rdbl_output)

        await tools.tool_read_block(mgr, "abc12345", 0, key="FFFFFFFFFFFF", key_type="B")

        cmd = mgr.run_command.call_args[0][1]
        assert cmd.endswith(" -b")  # key type B flag at end of command
        assert " -a" not in cmd

    @pytest.mark.asyncio
    async def test_read_block_auth_failure(self, hf_mf_rdbl_auth_fail_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_mf_rdbl_auth_fail_output)

        result = await tools.tool_read_block(mgr, "abc12345", 4)

        assert result["success"] is False
        assert "error" in result
        assert result["error"]

    @pytest.mark.asyncio
    async def test_read_block_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_read_block(mgr, "abc12345", 0)

        assert "error" in result


# ---------------------------------------------------------------------------
# TestDumpTag
# ---------------------------------------------------------------------------

class TestDumpTag:
    @pytest.mark.asyncio
    async def test_dump_mf1k_success(self, dump_success_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(dump_success_output)

        result = await tools.tool_dump_tag(mgr, "abc12345", "mf1k")

        assert result["success"] is True
        assert result["output_file"] is not None
        mgr.run_command.assert_called_once()
        cmd = mgr.run_command.call_args[0][1]
        assert "hf mf dump" in cmd

    @pytest.mark.asyncio
    async def test_dump_mf1k_timeout_arg(self, dump_success_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(dump_success_output)

        await tools.tool_dump_tag(mgr, "abc12345", "mf1k")

        kwargs = mgr.run_command.call_args[1]
        assert kwargs.get("timeout") == 120

    @pytest.mark.asyncio
    async def test_dump_mf4k_uses_4k_flag(self, dump_success_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(dump_success_output)

        await tools.tool_dump_tag(mgr, "abc12345", "mf4k")

        cmd = mgr.run_command.call_args[0][1]
        assert "--4k" in cmd

    @pytest.mark.asyncio
    async def test_dump_mfu_uses_mfu_command(self, dump_success_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(dump_success_output)

        await tools.tool_dump_tag(mgr, "abc12345", "mfu")

        cmd = mgr.run_command.call_args[0][1]
        assert "hf mfu dump" in cmd

    @pytest.mark.asyncio
    async def test_dump_unsupported_type_returns_error(self):
        mgr = _make_manager()

        result = await tools.tool_dump_tag(mgr, "abc12345", "em410x")

        assert "error" in result
        assert "unsupported" in result["error"].lower()
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_dump_with_key_file(self, dump_success_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(dump_success_output)

        key_path = str(tmp_path / "keys.dic")
        await tools.tool_dump_tag(mgr, "abc12345", "mf1k", key_file=key_path)

        cmd = mgr.run_command.call_args[0][1]
        assert f"-f {key_path}" in cmd

    @pytest.mark.asyncio
    async def test_dump_nonexistent_session(self):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = None

        result = await tools.tool_dump_tag(mgr, "nonexistent", "mf1k")

        assert "error" in result
        mgr.run_command.assert_not_called()


# ---------------------------------------------------------------------------
# TestAutopwn
# ---------------------------------------------------------------------------

class TestAutopwn:
    @pytest.mark.asyncio
    async def test_autopwn_success_complete(self, autopwn_all_default_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(autopwn_all_default_output)

        result = await tools.tool_autopwn(mgr, "abc12345")

        assert result["complete"] is True
        assert len(result["keys"]) == 16

    @pytest.mark.asyncio
    async def test_autopwn_command_is_plain(self, autopwn_all_default_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(autopwn_all_default_output)

        await tools.tool_autopwn(mgr, "abc12345")

        cmd = mgr.run_command.call_args[0][1]
        assert cmd == "hf mf autopwn"

    @pytest.mark.asyncio
    async def test_autopwn_timeout_300(self, autopwn_all_default_output, tmp_path):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = tmp_path / "artifacts"
        mgr.run_command.return_value = _run_ok(autopwn_all_default_output)

        await tools.tool_autopwn(mgr, "abc12345")

        kwargs = mgr.run_command.call_args[1]
        assert kwargs.get("timeout") == 600

    @pytest.mark.asyncio
    async def test_autopwn_nonexistent_session(self):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = None

        result = await tools.tool_autopwn(mgr, "nonexistent")

        assert "error" in result
        mgr.run_command.assert_not_called()


# ---------------------------------------------------------------------------
# TestDarkside
# ---------------------------------------------------------------------------

class TestDarkside:
    @pytest.mark.asyncio
    async def test_darkside_success(self, darkside_success_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(darkside_success_output)

        result = await tools.tool_darkside(mgr, "abc12345")

        assert result["success"] is True
        assert result["key"] == "A0A1A2A3A4A5"

    @pytest.mark.asyncio
    async def test_darkside_not_vulnerable(self, darkside_fail_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(darkside_fail_output)

        result = await tools.tool_darkside(mgr, "abc12345")

        assert result["success"] is False
        assert result["key"] is None
        assert result["error"]

    @pytest.mark.asyncio
    async def test_darkside_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_darkside(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestNested
# ---------------------------------------------------------------------------

class TestNested:
    @pytest.mark.asyncio
    async def test_nested_command_construction_key_a(self, hardnested_success_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hardnested_success_output)

        await tools.tool_nested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 4, "A")

        cmd = mgr.run_command.call_args[0][1]
        # sector 0 trailer is block 3, sector 4 trailer is block 19
        assert "--blk 3" in cmd
        assert "--tblk 19" in cmd
        assert "-a" in cmd
        assert "--ta" in cmd

    @pytest.mark.asyncio
    async def test_nested_command_construction_key_b(self, hardnested_success_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hardnested_success_output)

        await tools.tool_nested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 4, "B")

        cmd = mgr.run_command.call_args[0][1]
        assert "--tb" in cmd
        assert "--ta" not in cmd

    @pytest.mark.asyncio
    async def test_nested_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_nested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 1, "A")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestHardnested
# ---------------------------------------------------------------------------

class TestHardnested:
    @pytest.mark.asyncio
    async def test_hardnested_success(self, hardnested_success_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hardnested_success_output)

        result = await tools.tool_hardnested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 1, "A")

        assert result["success"] is True
        assert result["key"] == "4D57414C5648"

    @pytest.mark.asyncio
    async def test_hardnested_timeout_120(self, hardnested_success_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hardnested_success_output)

        await tools.tool_hardnested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 1, "A")

        kwargs = mgr.run_command.call_args[1]
        assert kwargs.get("timeout") == 120

    @pytest.mark.asyncio
    async def test_hardnested_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_hardnested(mgr, "abc12345", "FFFFFFFFFFFF", "A", 1, "A")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestChkKeys
# ---------------------------------------------------------------------------

class TestChkKeys:
    @pytest.mark.asyncio
    async def test_chk_keys_default(self, chk_keys_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(chk_keys_output)

        result = await tools.tool_chk_keys(mgr, "abc12345")

        assert "keys" in result
        assert "found_count" in result
        assert "total_sectors" in result

    @pytest.mark.asyncio
    async def test_chk_keys_custom_key_list(self, chk_keys_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(chk_keys_output)

        await tools.tool_chk_keys(mgr, "abc12345", key_list=["A0A1A2A3A4A5", "B0B1B2B3B4B5"])

        cmd = mgr.run_command.call_args[0][1]
        assert "-k A0A1A2A3A4A5" in cmd
        assert "-k B0B1B2B3B4B5" in cmd

    @pytest.mark.asyncio
    async def test_chk_keys_no_key_list_no_k_flags(self, chk_keys_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(chk_keys_output)

        await tools.tool_chk_keys(mgr, "abc12345")

        cmd = mgr.run_command.call_args[0][1]
        assert " -k " not in cmd

    @pytest.mark.asyncio
    async def test_chk_keys_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_chk_keys(mgr, "abc12345")

        assert "error" in result


# ---------------------------------------------------------------------------
# TestSniffStart
# ---------------------------------------------------------------------------

class TestSniffStart:
    @pytest.mark.asyncio
    async def test_sniff_start_iso15693(self):
        mgr = _make_manager()
        mgr.run_sniff = MagicMock(return_value=_run_ok("sniffing..."))

        result = await tools.tool_sniff_start(mgr, "abc12345", "15693")

        assert result["success"] is True
        assert result["protocol"] == "15693"
        cmd = mgr.run_sniff.call_args[0][1]
        assert "hf 15 sniff" in cmd

    @pytest.mark.asyncio
    async def test_sniff_start_14a(self):
        mgr = _make_manager()
        mgr.run_sniff = MagicMock(return_value=_run_ok("sniffing..."))

        result = await tools.tool_sniff_start(mgr, "abc12345", "14a")

        assert result["success"] is True
        cmd = mgr.run_sniff.call_args[0][1]
        assert "hf 14a sniff" in cmd

    @pytest.mark.asyncio
    async def test_sniff_start_iclass(self):
        mgr = _make_manager()
        mgr.run_sniff = MagicMock(return_value=_run_ok("sniffing..."))

        result = await tools.tool_sniff_start(mgr, "abc12345", "iclass")

        assert result["success"] is True
        cmd = mgr.run_sniff.call_args[0][1]
        assert "hf iclass sniff" in cmd

    @pytest.mark.asyncio
    async def test_sniff_start_invalid_protocol(self):
        mgr = _make_manager()
        mgr.run_sniff = MagicMock()

        result = await tools.tool_sniff_start(mgr, "abc12345", "lf134")

        assert "error" in result
        assert "unsupported" in result["error"].lower()
        mgr.run_sniff.assert_not_called()

    @pytest.mark.asyncio
    async def test_sniff_start_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_sniff = MagicMock(side_effect=KeyError("abc12345"))

        result = await tools.tool_sniff_start(mgr, "abc12345", "14a")

        assert "error" in result
        assert "abc12345" in result["error"]


# ---------------------------------------------------------------------------
# TestSniffStop
# ---------------------------------------------------------------------------

class TestSniffStop:
    @pytest.mark.asyncio
    async def test_sniff_stop_with_data(
        self, hw_status_with_trace_output, trace_list_iso15693_output
    ):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = Path("/tmp/artifacts")
        mgr.run_command.side_effect = [
            _run_ok(hw_status_with_trace_output),   # hw status
            _run_ok(""),                             # trace save
            _run_ok(""),                             # trace load
            _run_ok(trace_list_iso15693_output),    # trace list
        ]

        result = await tools.tool_sniff_stop(mgr, "abc12345", "15693")

        assert result["captured"] is True
        assert result["trace_bytes"] == 741
        assert result["trace_file"] == "/tmp/artifacts/trace-15693"
        assert len(result["exchanges"]) > 0
        assert isinstance(result["exchange_count"], int)
        assert result["exchange_count"] == len(result["exchanges"])
        assert isinstance(result["auth_nonces"], list)
        # Verify trace load and trace list are separate commands (no semicolons)
        assert mgr.run_command.call_count == 4
        cmds = [call[0][1] for call in mgr.run_command.call_args_list]
        assert cmds[1] == "trace save -f /tmp/artifacts/trace-15693"
        assert cmds[2] == "trace load -f /tmp/artifacts/trace-15693"
        assert cmds[3] == "trace list -t 15"
        for cmd in cmds:
            assert ";" not in cmd

    @pytest.mark.asyncio
    async def test_sniff_stop_empty_trace(self, hw_status_no_trace_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hw_status_no_trace_output)

        result = await tools.tool_sniff_stop(mgr, "abc12345", "15693")

        assert result["captured"] is False
        assert "message" in result
        # Should not proceed past the hw status check
        assert mgr.run_command.call_count == 1

    @pytest.mark.asyncio
    async def test_sniff_stop_nonexistent_session(self):
        mgr = _make_manager()
        mgr.run_command.side_effect = KeyError("abc12345")

        result = await tools.tool_sniff_stop(mgr, "abc12345", "14a")

        assert "error" in result
        assert "abc12345" in result["error"]


# ---------------------------------------------------------------------------
# TestInputValidation -- validator functions
# ---------------------------------------------------------------------------

from pm3_mcp.tools import (
    _validate_hex,
    _validate_hex_data,
    _validate_block,
    _validate_sector,
    _validate_no_injection,
    _validate_path,
    _validate_key_type,
)


class TestInputValidation:
    def test_hex_key_valid(self):
        _validate_hex("FFFFFFFFFFFF", 12, "key")  # should not raise

    def test_hex_key_lowercase_valid(self):
        _validate_hex("aabbccddeeff", 12, "key")  # should not raise

    def test_hex_key_with_semicolon(self):
        with pytest.raises(ValueError, match="hex-only"):
            _validate_hex("FFFFFF;hf mf", 12, "key")

    def test_hex_key_wrong_length(self):
        with pytest.raises(ValueError, match="12 hex chars"):
            _validate_hex("FFFF", 12, "key")

    def test_hex_key_with_spaces(self):
        with pytest.raises(ValueError, match="hex-only"):
            _validate_hex("FF FF FF FF FF FF", 12, "key")

    def test_hex_16_valid(self):
        _validate_hex("AE A2 A6 A8 F5 43 21 00".replace(" ", ""), 16, "key")

    def test_block_valid_zero(self):
        _validate_block(0)

    def test_block_valid_max(self):
        _validate_block(255)

    def test_block_negative(self):
        with pytest.raises(ValueError, match="Block"):
            _validate_block(-1)

    def test_block_overflow(self):
        with pytest.raises(ValueError, match="Block"):
            _validate_block(256)

    def test_block_float_rejected(self):
        with pytest.raises(ValueError, match="Block"):
            _validate_block(1.5)

    def test_sector_valid(self):
        _validate_sector(0)
        _validate_sector(39)

    def test_sector_negative(self):
        with pytest.raises(ValueError, match="Sector"):
            _validate_sector(-1)

    def test_sector_overflow(self):
        with pytest.raises(ValueError, match="Sector"):
            _validate_sector(40)

    def test_no_injection_semicolon(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("FFFFFFFFFFFF; hw reset", "key")

    def test_no_injection_pipe(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("test | rm -rf", "param")

    def test_no_injection_backtick(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("key`whoami`", "param")

    def test_no_injection_dollar(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("$HOME/file", "param")

    def test_no_injection_redirect(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("file > /dev/null", "param")

    def test_no_injection_ampersand(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_no_injection("cmd & bg", "param")

    def test_no_injection_clean_string(self):
        _validate_no_injection("FFFFFFFFFFFF", "key")  # should not raise

    def test_path_safe(self):
        _validate_path("/tmp/dump.bin", "path")  # should not raise

    def test_path_with_dashes_and_dots(self):
        _validate_path("/tmp/engagements/my-tag/artifacts/trace-14a.bin", "path")

    def test_path_injection(self):
        with pytest.raises(ValueError, match="dangerous"):
            _validate_path("/tmp/dump.bin; rm -rf /", "path")

    def test_hex_data_valid(self):
        _validate_hex_data("00112233", "data")  # should not raise

    def test_hex_data_odd_length(self):
        with pytest.raises(ValueError, match="even length"):
            _validate_hex_data("001", "data")

    def test_hex_data_non_hex(self):
        with pytest.raises(ValueError, match="hex-only"):
            _validate_hex_data("GGHHII", "data")

    def test_key_type_valid(self):
        _validate_key_type("A")
        _validate_key_type("B")
        _validate_key_type("a")
        _validate_key_type("b")

    def test_key_type_invalid(self):
        with pytest.raises(ValueError, match="key_type"):
            _validate_key_type("C")


# ---------------------------------------------------------------------------
# TestCommandInjectionPrevention -- end-to-end tool rejection
# ---------------------------------------------------------------------------

class TestCommandInjectionPrevention:
    """Verify that tool functions reject parameters containing injection payloads.

    Each test confirms that a semicolon (or other dangerous char) in a
    user-supplied parameter returns an error dict instead of building a
    command string.
    """

    @pytest.mark.asyncio
    async def test_read_block_rejects_semicolon_key(self):
        mgr = _make_manager()
        result = await tools.tool_read_block(
            mgr, "sess", 0, key="FFFFFF;hw reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_block_rejects_bad_key_type(self):
        mgr = _make_manager()
        result = await tools.tool_read_block(
            mgr, "sess", 0, key="FFFFFFFFFFFF", key_type="C"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_read_block_rejects_negative_block(self):
        mgr = _make_manager()
        result = await tools.tool_read_block(mgr, "sess", -1)
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_mf_wrbl_rejects_injection_data(self):
        mgr = _make_manager()
        result = await tools.tool_mf_wrbl(
            mgr, "sess", 0, "FFFFFFFFFFFF", "A", "00;hw reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_mf_wrbl_rejects_short_data(self):
        mgr = _make_manager()
        result = await tools.tool_mf_wrbl(
            mgr, "sess", 0, "FFFFFFFFFFFF", "A", "00FF"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_mf_wrbl_rejects_injection_key(self):
        mgr = _make_manager()
        result = await tools.tool_mf_wrbl(
            mgr, "sess", 0,
            "FFFFFFFFFFFF; hf mf wrbl --blk 3 -k FFFFFFFFFFFF -a -d 00000000000000FF078069FFFFFFFFFFFF",
            "A", "00112233445566778899AABBCCDDEEFF",
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_nested_rejects_injection_key(self):
        mgr = _make_manager()
        result = await tools.tool_nested(
            mgr, "sess", "FFFFFF;reset", "A", 1, "A"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_hardnested_rejects_injection_key(self):
        mgr = _make_manager()
        result = await tools.tool_hardnested(
            mgr, "sess", "FFFFFF|reset", "A", 1, "A"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_chk_keys_rejects_injection_in_list(self):
        mgr = _make_manager()
        result = await tools.tool_chk_keys(
            mgr, "sess", key_list=["FFFFFFFFFFFF", "AABBCC;reset"]
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_dump_tag_rejects_injection_key_file(self):
        mgr = _make_manager()
        result = await tools.tool_dump_tag(
            mgr, "sess", "mf1k", key_file="/tmp/keys.dic; rm -rf /"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_desfire_files_rejects_injection_aid(self):
        mgr = _make_manager()
        result = await tools.tool_desfire_files(
            mgr, "sess", "000357; hw reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iclass_rdbl_rejects_injection_key(self):
        mgr = _make_manager()
        result = await tools.tool_iclass_rdbl(
            mgr, "sess", 5, key="AE A2A6A8;reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iclass_wrbl_rejects_injection_data(self):
        mgr = _make_manager()
        result = await tools.tool_iclass_wrbl(
            mgr, "sess", 7, "AEA2A6A8F5432100", "0011;reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iso15693_wrbl_rejects_injection_data(self):
        mgr = _make_manager()
        result = await tools.tool_iso15693_wrbl(
            mgr, "sess", 0, "AABB;reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_mf_restore_rejects_injection_dump_file(self):
        mgr = _make_manager()
        result = await tools.tool_mf_restore(
            mgr, "sess", "/tmp/dump.bin; rm -rf /"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_mf_restore_rejects_injection_key_file(self):
        mgr = _make_manager()
        result = await tools.tool_mf_restore(
            mgr, "sess", "/tmp/dump.bin", key_file="/tmp/keys; rm -rf /"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iclass_dump_rejects_injection_key(self):
        mgr = _make_manager()
        result = await tools.tool_iclass_dump(
            mgr, "sess", key="AABBCCDD;reset"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iclass_loclass_rejects_injection_trace_file(self):
        mgr = _make_manager()
        result = await tools.tool_iclass_loclass(
            mgr, "sess", trace_file="/tmp/trace; rm -rf /"
        )
        assert "error" in result
        mgr.run_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_iso15693_rdbl_rejects_negative_block(self):
        mgr = _make_manager()
        result = await tools.tool_iso15693_rdbl(mgr, "sess", -1)
        assert "error" in result
        mgr.run_command.assert_not_called()
