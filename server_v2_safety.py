from pathlib import Path
import json

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe_workspace")


ALLOWED_ROOTS = [
    Path("/media/totem_disk/totem/jizheng/workspace_2026/agent_learn").resolve(),
]


def check_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()

    for root in ALLOWED_ROOTS:
        if p == root or root in p.parents:
            return p

    raise PermissionError(f"path outside allowed roots: {p}")


@mcp.tool()
def ping(message: str = "hello") -> str:
    """
    Test whether the safe_workspace MCP server is connected.
    """
    return f"pong: {message}"


@mcp.tool()
def safe_write_file(path: str, content: str, mode: str = "w") -> str:
    """
    Safely write unicode text to a file inside the allowed workspace.

    Args:
        path: Target file path. Must be inside the allowed workspace.
        content: Unicode text content to write.
        mode: Write mode. Use "w" to create a new file, "a" to append.
              "w" refuses to overwrite an existing file.
    """
    try:
        p = check_path(path)

        if mode not in ("w", "a"):
            return json.dumps({
                "status": "denied",
                "error_code": "unsupported_mode",
                "message": f"Only mode='w' and mode='a' are supported now, got: {mode}",
                "retryable": False,
            }, ensure_ascii=False)

        if mode == "w" and p.exists():
            return json.dumps({
                "status": "denied",
                "error_code": "file_exists",
                "message": f"File already exists, refuse to overwrite: {p}",
                "retryable": False,
            }, ensure_ascii=False)

        p.parent.mkdir(parents=True, exist_ok=True)

        if mode == "w":
            p.write_text(content, encoding="utf-8")
        else:
            with p.open("a", encoding="utf-8") as f:
                f.write(content)

        return json.dumps({
            "status": "ok",
            "path": str(p),
            "mode": mode,
            "bytes": len(content.encode("utf-8")),
            "message": "write completed",
        }, ensure_ascii=False)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e),
            "retryable": False,
        }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
