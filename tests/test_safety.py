"""Tests for the three-tier safety model."""

import pytest
from pm3_mcp.safety import SafetyTier, classify_tool


class TestClassifyTool:
    def test_read_only_tools(self):
        for tool in ["hw_status", "detect_tag", "hf_info", "lf_info",
                     "read_block", "dump_tag",
                     "autopwn", "darkside", "nested", "hardnested", "chk_keys",
                     "desfire_info", "desfire_apps", "desfire_files",
                     "iclass_info", "iclass_rdbl", "iso15693_info", "iso15693_rdbl",
                     "iclass_dump", "iso15693_dump", "iclass_chk", "iclass_loclass"]:
            assert classify_tool(tool) == SafetyTier.READ_ONLY

    def test_allowed_write_tools(self):
        for tool in ["connect", "disconnect", "sniff_start", "sniff_stop"]:
            assert classify_tool(tool) == SafetyTier.ALLOWED_WRITE

    def test_approval_write_tools(self):
        for tool in ["mf_wrbl", "mf_restore", "iclass_wrbl", "iso15693_wrbl"]:
            assert classify_tool(tool) == SafetyTier.APPROVAL_WRITE

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            classify_tool("write_block")
