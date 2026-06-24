import json

import pytest

from pm3_mcp.server import call_tool


@pytest.mark.asyncio
async def test_legacy_project_path_rejected():
    """Hard rename: a legacy project_path arg fails loud, not silent."""
    result = await call_tool("connect", {"project_path": "/tmp/x"})
    payload = json.loads(result[0].text)
    assert "engagement_path" in payload["error"]
    assert "project_path" in payload["error"]
