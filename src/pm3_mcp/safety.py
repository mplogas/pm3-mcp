"""Three-tier safety model for PM3 MCP tools.

Tiers:
  read-only       -- full autonomy, no side effects
  allowed-write   -- autonomous, all calls logged
  approval-write  -- blocks until human confirms
"""

from __future__ import annotations

from enum import Enum


class SafetyTier(Enum):
    READ_ONLY = "read-only"
    ALLOWED_WRITE = "allowed-write"
    APPROVAL_WRITE = "approval-write"


_TOOL_TIERS: dict[str, SafetyTier] = {
    "hw_status": SafetyTier.READ_ONLY,
    "detect_tag": SafetyTier.READ_ONLY,
    "hf_info": SafetyTier.READ_ONLY,
    "lf_info": SafetyTier.READ_ONLY,
    "read_block": SafetyTier.READ_ONLY,
    "dump_tag": SafetyTier.READ_ONLY,
    "autopwn": SafetyTier.READ_ONLY,
    "darkside": SafetyTier.READ_ONLY,
    "nested": SafetyTier.READ_ONLY,
    "hardnested": SafetyTier.READ_ONLY,
    "chk_keys": SafetyTier.READ_ONLY,
    "desfire_info": SafetyTier.READ_ONLY,
    "desfire_apps": SafetyTier.READ_ONLY,
    "desfire_files": SafetyTier.READ_ONLY,
    "iclass_info": SafetyTier.READ_ONLY,
    "iclass_rdbl": SafetyTier.READ_ONLY,
    "iso15693_info": SafetyTier.READ_ONLY,
    "iso15693_rdbl": SafetyTier.READ_ONLY,
    "iclass_dump": SafetyTier.READ_ONLY,
    "iso15693_dump": SafetyTier.READ_ONLY,
    "iclass_chk": SafetyTier.READ_ONLY,
    "iclass_loclass": SafetyTier.READ_ONLY,
    "connect": SafetyTier.ALLOWED_WRITE,
    "disconnect": SafetyTier.ALLOWED_WRITE,
    "mf_wrbl": SafetyTier.APPROVAL_WRITE,
    "mf_restore": SafetyTier.APPROVAL_WRITE,
    "iclass_wrbl": SafetyTier.APPROVAL_WRITE,
    "iso15693_wrbl": SafetyTier.APPROVAL_WRITE,
}


def classify_tool(tool_name: str) -> SafetyTier:
    """Return the safety tier for a tool name."""
    tier = _TOOL_TIERS.get(tool_name)
    if tier is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return tier
