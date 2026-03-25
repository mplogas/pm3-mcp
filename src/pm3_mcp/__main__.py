"""Allow running as: python -m pm3_mcp"""

from pm3_mcp.server import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
