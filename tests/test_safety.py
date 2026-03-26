"""Tests for the three-tier safety model."""

import pytest
from pm3_mcp.safety import SafetyTier, classify_tool


class TestClassifyTool:
    def test_read_only_tools(self):
        for tool in ["hw_status", "detect_tag", "hf_info", "lf_info",
                     "read_block", "dump_tag",
                     "autopwn", "darkside", "nested", "hardnested", "chk_keys",
                     "desfire_info", "desfire_apps", "desfire_files",
                     "iclass_info", "iclass_rdbl", "iso15693_info", "iso15693_rdbl"]:
            assert classify_tool(tool) == SafetyTier.READ_ONLY

    def test_allowed_write_tools(self):
        for tool in ["connect", "disconnect"]:
            assert classify_tool(tool) == SafetyTier.ALLOWED_WRITE

    def test_no_approval_write_tools_in_mvp(self):
        """MVP has no approval-write tools. The tier exists for forward compat."""
        from pm3_mcp.safety import _TOOL_TIERS
        approval_tools = [
            name for name, tier in _TOOL_TIERS.items()
            if tier == SafetyTier.APPROVAL_WRITE
        ]
        assert approval_tools == []

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            classify_tool("write_block")
