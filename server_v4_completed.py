from __future__ import annotations

from pathlib import Path
from datetime import datetime
import json
import subprocess

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("safe_workspace")

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "safe_workspace_policy.json"
STATE_PATH = BASE_DIR / "safe_workspace_state.json"


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def j(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def load_policy() -> dict:
    if not POLICY_PATH.exists():
        raise RuntimeError(f"Policy file not found: {POLICY_PATH}")

    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    allow_roots = [Path(p).expanduser().resolve() for p in policy.get("allow_roots", [])]
    deny_paths = [Path(p).expanduser().resolve() for p in policy.get("deny_paths", [])]

    # 强制保护配置文件和状态文件
    deny_paths.append(POLICY_PATH.resolve())
    deny_paths.append(STATE_PATH.resolve())

    # 强制保护每个白名单 root 里的 .git
    for root in allow_roots:
        deny_paths.append((root / ".git").resolve())

    return {
        "allow_roots": allow_roots,
        "deny_paths": deny_paths,
        "blocked_extensions": set(policy.get("blocked_extensions", [])),
    }


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {"managed": {}, "unmanaged": {}}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"managed": {}, "unmanaged": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def match_under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def check_write_path(path: str) -> Path:
    policy = load_policy()
    p = Path(path).expanduser().resolve()

    if not any(match_under(p, root) for root in policy["allow_roots"]):
        raise PermissionError(f"path outside allowed roots: {p}")

    for denied in policy["deny_paths"]:
        if match_under(p, denied):
            raise PermissionError(f"path is denied by policy: {p}")

    if p.suffix.lower() in policy["blocked_extensions"]:
        raise PermissionError(f"blocked extension: {p.suffix}")

    return p


def allowed_root_for(path: Path) -> Path:
    policy = load_policy()
    roots = [root for root in policy["allow_roots"] if match_under(path, root)]
    if not roots:
        raise PermissionError(f"path outside allowed roots: {path}")
    return max(roots, key=lambda x: len(str(x)))


def run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "git",
            "-c", "user.name=QwenPaw-Agent",
            "-c", "user.email=qwenpaw-agent.local",
            *args,
        ],
        cwd=str(cwd),
        text=True,
        capture_output=True,
    )

def ensure_repo(path: Path) -> Path:
    root = allowed_root_for(path)

    # 只允许在 allow_root 内部寻找 git repo，不能向上越过 root
    cur = path if path.is_dir() else path.parent
    cur = cur.resolve()

    while True:
        if (cur / ".git").exists():
            return cur

        if cur == root:
            break

        if root not in cur.parents:
            break

        cur = cur.parent

    # 如果 allow_root 内部没有 git repo，就只在 allow_root 初始化
    r = run_git(["init"], root)
    if r.returncode != 0:
        raise RuntimeError(f"git init failed: {r.stderr.strip() or r.stdout.strip()}")

    return root

def is_git_tracked(path: Path, repo: Path) -> bool:
    rel = path.relative_to(repo)
    r = run_git(["ls-files", "--error-unmatch", str(rel)], repo)
    return r.returncode == 0


def commit_file(path: Path, message: str) -> dict:
    repo = ensure_repo(path)
    rel = path.relative_to(repo)

    run_git(["add", str(rel)], repo)

    diff = run_git(["diff", "--cached", "--quiet"], repo)
    if diff.returncode == 0:
        return {
            "git": "no_changes",
            "repo": str(repo),
        }

    r = run_git(["commit", "-m", message], repo)
    if r.returncode != 0:
        return {
            "git": "commit_failed",
            "repo": str(repo),
            "stderr": r.stderr.strip(),
            "stdout": r.stdout.strip(),
        }

    head = run_git(["rev-parse", "--short", "HEAD"], repo)
    return {
        "git": "committed",
        "repo": str(repo),
        "commit": head.stdout.strip(),
    }


def git_rm_and_commit(path: Path, message: str) -> dict:
    repo = ensure_repo(path)
    rel = path.relative_to(repo)

    r = run_git(["rm", str(rel)], repo)
    if r.returncode != 0:
        return {
            "git": "git_rm_failed",
            "repo": str(repo),
            "stderr": r.stderr.strip(),
            "stdout": r.stdout.strip(),
        }

    r = run_git(["commit", "-m", message], repo)
    if r.returncode != 0:
        return {
            "git": "commit_failed",
            "repo": str(repo),
            "stderr": r.stderr.strip(),
            "stdout": r.stdout.strip(),
        }

    head = run_git(["rev-parse", "--short", "HEAD"], repo)
    return {
        "git": "committed",
        "repo": str(repo),
        "commit": head.stdout.strip(),
    }


def is_managed(path: Path) -> bool:
    state = load_state()
    key = str(path.resolve())

    if key in state.get("managed", {}):
        return True

    try:
        repo = ensure_repo(path)
        return path.exists() and is_git_tracked(path, repo)
    except Exception:
        return False


def mark_file(path: Path, git_managed: bool) -> None:
    state = load_state()
    key = str(path.resolve())

    state.setdefault("managed", {})
    state.setdefault("unmanaged", {})

    if git_managed:
        state["managed"][key] = {"path": key, "created_at": now()}
        state["unmanaged"].pop(key, None)
    else:
        state["unmanaged"][key] = {"path": key, "created_at": now()}
        state["managed"].pop(key, None)

    save_state(state)


def unmark_file(path: Path) -> None:
    state = load_state()
    key = str(path.resolve())
    state.setdefault("managed", {}).pop(key, None)
    state.setdefault("unmanaged", {}).pop(key, None)
    save_state(state)


def write_result(status: str, **kwargs) -> str:
    data = {"status": status, **kwargs}
    return j(data)


@mcp.tool()
def ping(message: str = "hello") -> str:
    """
    Test whether the safe_workspace MCP server is connected.
    """
    return f"pong: {message}"


@mcp.tool()
def safe_create_text_file(path: str, content: str, git_managed: bool = True) -> str:
    """
    Create a new unicode text file inside allowed roots.

    Refuses to overwrite existing files.
    If git_managed is true, the file is added and committed to local git.
    """
    try:
        p = check_write_path(path)

        if p.exists():
            return write_result(
                "denied",
                error_code="file_exists",
                message=f"File already exists, refuse to overwrite: {p}",
                retryable=False,
            )

        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        mark_file(p, git_managed)

        git_info = None
        if git_managed:
            git_info = commit_file(p, f"agent create {p.name}")

        return write_result(
            "ok",
            action="create",
            path=str(p),
            bytes=len(content.encode("utf-8")),
            git_managed=git_managed,
            git=git_info,
            message="file created",
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_append_text_file(path: str, content: str) -> str:
    """
    Append unicode text to an existing file inside allowed roots.

    If the file is git-managed, the append is committed to local git.
    """
    try:
        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist, use safe_create_text_file first: {p}",
                retryable=False,
            )

        with p.open("a", encoding="utf-8") as f:
            f.write(content)

        git_info = None
        if is_managed(p):
            git_info = commit_file(p, f"agent append {p.name}")

        return write_result(
            "ok",
            action="append",
            path=str(p),
            bytes=len(content.encode("utf-8")),
            git=git_info,
            message="append completed",
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_rewrite_text_file(path: str, content: str) -> str:
    """
    Rewrite an existing unicode text file inside allowed roots.

    This is a whole-document rewrite.
    If the file is git-managed, the rewrite is committed to local git.
    """
    try:
        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist, use safe_create_text_file first: {p}",
                retryable=False,
            )

        p.write_text(content, encoding="utf-8")

        git_info = None
        if is_managed(p):
            git_info = commit_file(p, f"agent rewrite {p.name}")

        return write_result(
            "ok",
            action="rewrite",
            path=str(p),
            bytes=len(content.encode("utf-8")),
            git=git_info,
            message="rewrite completed",
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_replace_text_file(path: str, old: str, new: str, count: int = 0) -> str:
    """
    Replace text inside an existing unicode text file.

    It does NOT require the old text to be unique.
    count = 0 means replace all occurrences.
    count > 0 means replace only the first count occurrences.
    If the file is git-managed, the update is committed to local git.
    """
    try:
        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist: {p}",
                retryable=False,
            )

        text = p.read_text(encoding="utf-8")
        occurrences = text.count(old)

        if occurrences == 0:
            return write_result(
                "denied",
                error_code="old_text_not_found",
                message="old text not found",
                retryable=False,
            )

        if count < 0:
            return write_result(
                "denied",
                error_code="invalid_count",
                message="count must be >= 0",
                retryable=False,
            )

        replace_count = occurrences if count == 0 else min(count, occurrences)
        updated = text.replace(old, new, replace_count)
        p.write_text(updated, encoding="utf-8")

        git_info = None
        if is_managed(p):
            git_info = commit_file(p, f"agent replace {p.name}")

        return write_result(
            "ok",
            action="replace",
            path=str(p),
            occurrences=occurrences,
            replaced=replace_count,
            git=git_info,
            message="replace completed",
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_delete_file(path: str) -> str:
    """
    Delete a file inside allowed roots.

    If the file is git-managed, deletion uses git rm and commits locally.
    Otherwise it is removed directly.
    """
    try:
        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist: {p}",
                retryable=False,
            )

        if p.is_dir():
            return write_result(
                "denied",
                error_code="is_directory",
                message=f"Refuse to delete directory: {p}",
                retryable=False,
            )

        if is_managed(p):
            git_info = git_rm_and_commit(p, f"agent delete {p.name}")
        else:
            p.unlink()
            git_info = None

        unmark_file(p)

        return write_result(
            "ok",
            action="delete",
            path=str(p),
            git=git_info,
            message="delete completed",
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_git_status(path: str = "") -> str:
    """
    Show local git status for an allowed workspace path.

    This tool does not modify files.
    """
    try:
        if path:
            p = check_write_path(path)
        else:
            p = load_policy()["allow_roots"][0]

        repo = ensure_repo(p)
        r = run_git(["status", "--short"], repo)

        return write_result(
            "ok",
            action="git_status",
            repo=str(repo),
            stdout=r.stdout,
            stderr=r.stderr,
            returncode=r.returncode,
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


# 兼容旧测试用法：mode=w 新建，mode=a 追加
@mcp.tool()
def safe_write_file(path: str, content: str, mode: str = "w", git_managed: bool = True) -> str:
    """
    Backward-compatible wrapper.

    mode='w': create new text file, refuse overwrite.
    mode='a': append to existing text file.
    Prefer safe_create_text_file / safe_append_text_file for new workflows.
    """
    if mode == "w":
        return safe_create_text_file(path=path, content=content, git_managed=git_managed)
    if mode == "a":
        return safe_append_text_file(path=path, content=content)

    return write_result(
        "denied",
        error_code="unsupported_mode",
        message=f"Only mode='w' and mode='a' are supported by safe_write_file, got: {mode}",
        retryable=False,
    )


if __name__ == "__main__":
    mcp.run()
