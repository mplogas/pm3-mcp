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
        mgr.connect.assert_called_once_with("my-tag", port="/dev/ttyACM0")

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
        mgr.connect.assert_called_once_with("auto-tag", port=None)

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
    async def test_detect_tag_returns_raw_output(self):
        output = "[+] Detected tag: MIFARE Classic 1K"
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(output)

        result = await tools.tool_detect_tag(mgr, "abc12345")

        assert result["raw"] == output
        assert result["success"] is True
        mgr.run_command.assert_called_once_with("abc12345", "auto", timeout=45)

    @pytest.mark.asyncio
    async def test_detect_tag_no_tag(self):
        output = "[!] No tag detected"
        mgr = _make_manager()
        mgr.run_command.return_value = {"success": False, "output": output, "returncode": 1}

        result = await tools.tool_detect_tag(mgr, "abc12345")

        assert result["raw"] == output
        assert result["success"] is False

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
        assert "--ka" in cmd
        assert "--kb" not in cmd

    @pytest.mark.asyncio
    async def test_read_block_uses_key_b_flag(self, hf_mf_rdbl_output):
        mgr = _make_manager()
        mgr.run_command.return_value = _run_ok(hf_mf_rdbl_output)

        await tools.tool_read_block(mgr, "abc12345", 0, key="FFFFFFFFFFFF", key_type="B")

        cmd = mgr.run_command.call_args[0][1]
        assert "--kb" in cmd
        assert "--ka" not in cmd

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

        await tools.tool_dump_tag(mgr, "abc12345", "mf1k", key_file="/tmp/keys.dic")

        cmd = mgr.run_command.call_args[0][1]
        assert "-f /tmp/keys.dic" in cmd

    @pytest.mark.asyncio
    async def test_dump_nonexistent_session(self):
        mgr = _make_manager()
        mgr.get_artifacts_path.return_value = None

        result = await tools.tool_dump_tag(mgr, "nonexistent", "mf1k")

        assert "error" in result
        mgr.run_command.assert_not_called()
