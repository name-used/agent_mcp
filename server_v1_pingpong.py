from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe_workspace")


@mcp.tool()
def ping(message: str = "hello") -> str:
    """
    Test whether the safe_workspace MCP server is connected.

    Args:
        message: Any text message.

    Returns:
        A simple pong response.
    """
    return f"pong: {message}"


if __name__ == "__main__":
    mcp.run()
