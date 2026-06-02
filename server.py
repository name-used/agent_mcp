from __future__ import annotations

from pathlib import Path
from datetime import datetime
import json
import os
import sys
import subprocess
import shutil
from typing import Any

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("safe_workspace")

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "safe_workspace_policy.json"
STATE_PATH = BASE_DIR / "safe_workspace_state.json"


# ============================================================
# 代码级总开关
# ------------------------------------------------------------
# 你的设计目标是“不防心坏，只防发疯”：
# - 写文件：只能写 allow_roots 内，避开 deny_paths，自动 git 提交
# - .git / policy / state 默认禁止 Agent 直接修改
# - Python 运行：只运行 run_python.allow_paths 里的入口脚本
# - Python 脚本内部是否访问沙箱外文件，不由本 MCP 层限制
# - CMD 查询：只开放极少数只读命令，且 shell=False，不接受任意 shell 字符串
#
# 如果你想临时彻底关掉某类工具，直接改这里即可。
# policy 里的 features 可以进一步关闭某项，但不能打开这里已经关闭的项。
# ============================================================
FEATURES = {
    "create_file": True,
    "append_file": True,
    "rewrite_file": True,
    "replace_file": True,
    "delete_file": True,
    "read_file": True,
    "list_dir": True,
    "grep_text": True,
    "readonly_cmd": True,
    "git_status": True,
    "git_log": True,
    "git_diff": True,
    "run_python": True,
}

# 只读 cmd 的代码级命令白名单。
# 注意：ll 不是系统命令，而是本工具内部映射为 ls -lah。
CODE_ALLOWED_READONLY_CMDS = {"ls", "ll", "grep"}

SHELL_CONTROL_TOKENS = {
    ">", ">>", "<", "<<", "|", "||", "&", "&&", ";",
    "2>", "2>>", "1>", "1>>", "&>", "&>>",
}

LS_ALLOWED_FLAGS = {
    "-a", "-l", "-h", "-d", "-R",
    "-la", "-al", "-lh", "-hl",
    "-lah", "-lha", "-alh", "-ahl", "-hal", "-hla",
    "--all", "--long", "--human-readable", "--directory", "--recursive",
}

GREP_ALLOWED_FLAGS = {
    "-n", "-i", "-r", "-I",
    "--line-number",
    "--ignore-case",
    "--recursive",
    "--binary-files=without-match",
}


# ============================================================
# 基础工具
# ============================================================

def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def j(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def write_result(status: str, **kwargs) -> str:
    data = {"status": status, **kwargs}
    return j(data)


def match_under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def load_raw_policy() -> dict:
    if not POLICY_PATH.exists():
        raise RuntimeError(f"Policy file not found: {POLICY_PATH}")
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def load_policy() -> dict:
    policy = load_raw_policy()

    allow_roots = [Path(p).expanduser().resolve() for p in policy.get("allow_roots", [])]
    deny_paths = [Path(p).expanduser().resolve() for p in policy.get("deny_paths", [])]

    # 强制保护配置文件和状态文件
    deny_paths.append(POLICY_PATH.resolve())
    deny_paths.append(STATE_PATH.resolve())

    # 强制保护每个白名单 root 里的 .git
    # Agent 不应该直接写 .git；git 只能由本 MCP 工具内部操作。
    for root in allow_roots:
        deny_paths.append((root / ".git").resolve())

    return {
        "allow_roots": allow_roots,
        "deny_paths": deny_paths,
        "blocked_extensions": set(policy.get("blocked_extensions", [])),
        "run_python": policy.get("run_python", {}),
        "run_cmd": policy.get("run_cmd", {}),
        "features": policy.get("features", {}),
    }


def feature_enabled(name: str, policy: dict | None = None) -> bool:
    """
    两层开关：
    1. FEATURES 是代码级硬开关。这里关掉后，policy 不能重新打开。
    2. policy.features 是配置级软开关，只能进一步关闭功能。
    """
    if not FEATURES.get(name, False):
        return False

    if policy is None:
        policy = load_policy()

    cfg_features = policy.get("features", {}) or {}
    return bool(cfg_features.get(name, True))


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {"managed": {}, "unmanaged": {}}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"managed": {}, "unmanaged": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def check_write_path(path: str | Path) -> Path:
    """
    写路径校验：
    - 必须在 allow_roots 内
    - 不能命中 deny_paths
    - 不能命中 blocked_extensions
    - resolve 后检查，阻止 symlink/path traversal 逃逸
    """
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


def check_read_path(path: str | Path, cwd: Path | None = None) -> Path:
    """
    读路径校验：
    - 必须在 allow_roots 内
    - 不能命中 deny_paths
    - 不检查 blocked_extensions，因为后者只限制写入
    - 相对路径会相对 cwd 解析
    """
    policy = load_policy()

    raw = Path(path).expanduser()
    if cwd is not None and not raw.is_absolute():
        raw = cwd / raw

    p = raw.resolve()

    if not any(match_under(p, root) for root in policy["allow_roots"]):
        raise PermissionError(f"path outside allowed roots: {p}")

    for denied in policy["deny_paths"]:
        if match_under(p, denied):
            raise PermissionError(f"path is denied by policy: {p}")

    return p


def allowed_root_for(path: Path) -> Path:
    policy = load_policy()
    roots = [root for root in policy["allow_roots"] if match_under(path, root)]
    if not roots:
        raise PermissionError(f"path outside allowed roots: {path}")
    return max(roots, key=lambda x: len(str(x)))


def resolve_policy_paths(paths: list[str]) -> list[Path]:
    return [Path(p).expanduser().resolve() for p in paths]


# ============================================================
# Python 运行白名单
# ============================================================

def match_run_path(path: Path, rule: Path) -> bool:
    """
    Python 运行白/黑名单路径匹配规则：
    - 规则以 .py 结尾：视为单文件规则，必须完全相等
    - 其它规则：视为目录规则，path 在目录下即可
    """
    if rule.suffix.lower() == ".py":
        return path == rule
    return match_under(path, rule)


def validate_run_args(args: list[str] | None, max_args: int, max_arg_len: int) -> list[str]:
    """
    只做 argv 层面的基本审查，不做 shell 字符过滤。
    safe_run_python_entry 使用 shell=False，`;`, `&&`, `|` 等不会被 shell 解释。
    Python 脚本本身的行为由 run_python.allow_paths 控制。
    """
    if args is None:
        return []

    if not isinstance(args, list):
        raise ValueError("args must be a list[str]")

    if len(args) > max_args:
        raise ValueError(f"too many args: {len(args)} > {max_args}")

    out = []
    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            raise ValueError(f"args[{i}] must be str")
        if "\x00" in arg:
            raise ValueError(f"args[{i}] contains null byte")
        if len(arg) > max_arg_len:
            raise ValueError(f"args[{i}] too long: {len(arg)} > {max_arg_len}")
        out.append(arg)

    return out


def build_run_env(run_policy: dict) -> dict:
    """
    默认继承当前 MCP server 的环境，便于复用 conda/venv/CUDA 等配置。
    如果需要更强隔离，可以在 policy 里设置 inherit_env=false。
    """
    if run_policy.get("inherit_env", True):
        env = dict(os.environ)
    else:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
        }

    env.update({str(k): str(v) for k, v in run_policy.get("extra_env", {}).items()})
    env.setdefault("PYTHONNOUSERSITE", "1")
    return env


# ============================================================
# Git 管理
# ============================================================

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
    """
    找到 path 所在 allow_root 内的 git repo。
    如果 allow_root 内没有 repo，就在 allow_root 初始化。

    注意：这是有意设计。
    你的沙箱目标是“每次修改都被 git 托管”，所以修改类工具可以触发 git init。
    """
    root = allowed_root_for(path)

    # 只允许在 allow_root 内部寻找 git repo，不能向上越过 root。
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

    # 如果 allow_root 内部没有 git repo，就只在 allow_root 初始化。
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


def validate_commit_ref(ref: str) -> str:
    ref = str(ref or "").strip()
    if not ref:
        raise ValueError("empty git ref")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-")
    if not all(ch in allowed for ch in ref):
        raise ValueError(f"bad git ref: {ref}")
    if ref.startswith("-"):
        raise ValueError(f"git ref must not start with '-': {ref}")
    return ref


# ============================================================
# 只读命令支持
# ============================================================

def reject_shell_tokens(args: list[str]) -> None:
    for arg in args:
        if arg in SHELL_CONTROL_TOKENS:
            raise ValueError(f"shell control token is forbidden: {arg}")

        # 拒绝常见重定向写法，比如 2>log.txt、>>out.txt。
        if arg.startswith((">", ">>", "2>", "2>>", "1>", "1>>", "&>", "&>>")):
            raise ValueError(f"shell redirection-like arg is forbidden: {arg}")


def get_run_cmd_config(policy: dict, cmd: str) -> dict:
    run_cmd = policy.get("run_cmd", {}) or {}
    commands = run_cmd.get("commands", {}) or {}

    # 如果 policy.run_cmd.commands 存在，就必须显式列出 command 才允许。
    # 如果 commands 为空，则使用代码默认白名单。
    if commands and cmd not in commands:
        raise PermissionError(f"command not enabled in policy: {cmd}")

    return commands.get(cmd, {}) if isinstance(commands.get(cmd, {}), dict) else {}


def resolve_cmd_bin(cmd: str, cmd_policy: dict) -> str:
    # ll 是内部别名，不需要系统里真的存在 ll。
    real_cmd = "ls" if cmd == "ll" else cmd
    bin_path = str(cmd_policy.get("bin", "")).strip()

    if not bin_path:
        bin_path = shutil.which(real_cmd) or ""

    if not bin_path:
        raise RuntimeError(f"command not found: {real_cmd}")

    p = Path(bin_path).expanduser().resolve()
    if not p.exists() or not p.is_file():
        raise RuntimeError(f"command bin is not a file: {p}")

    return str(p)


def parse_ls_args(args: list[str], cwd: Path) -> tuple[list[str], list[str]]:
    flags = []
    paths = []

    for arg in args:
        if arg.startswith("-"):
            if arg not in LS_ALLOWED_FLAGS:
                raise ValueError(f"ls flag is not allowed: {arg}")
            flags.append(arg)
        else:
            p = check_read_path(arg, cwd=cwd)
            paths.append(str(p))

    if not paths:
        paths = [str(cwd)]

    return flags, paths


def parse_grep_args(args: list[str], cwd: Path) -> tuple[list[str], str, list[str]]:
    flags = []
    rest = []

    for arg in args:
        if arg.startswith("-"):
            if arg not in GREP_ALLOWED_FLAGS:
                raise ValueError(f"grep flag is not allowed: {arg}")
            flags.append(arg)
        else:
            rest.append(arg)

    if not rest:
        raise ValueError("grep requires a pattern")

    pattern = rest[0]
    raw_paths = rest[1:] or ["."]

    paths = []
    for raw in raw_paths:
        p = check_read_path(raw, cwd=cwd)
        paths.append(str(p))

    return flags, pattern, paths


def validate_cmd_args(args: list[str] | None, max_args: int, max_arg_len: int) -> list[str]:
    if args is None:
        return []
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("args must be list[str]")
    if len(args) > max_args:
        raise ValueError(f"too many args: {len(args)} > {max_args}")
    for i, arg in enumerate(args):
        if "\x00" in arg:
            raise ValueError(f"args[{i}] contains null byte")
        if len(arg) > max_arg_len:
            raise ValueError(f"args[{i}] too long: {len(arg)} > {max_arg_len}")
    reject_shell_tokens(args)
    return args


# ============================================================
# MCP tools
# ============================================================

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
        policy = load_policy()
        if not feature_enabled("create_file", policy):
            return write_result("denied", error_code="feature_disabled", message="create_file is disabled")

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
        policy = load_policy()
        if not feature_enabled("append_file", policy):
            return write_result("denied", error_code="feature_disabled", message="append_file is disabled")

        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist, use safe_create_text_file first: {p}",
                retryable=False,
            )

        if p.is_dir():
            return write_result(
                "denied",
                error_code="is_directory",
                message=f"Refuse to append directory: {p}",
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
        policy = load_policy()
        if not feature_enabled("rewrite_file", policy):
            return write_result("denied", error_code="feature_disabled", message="rewrite_file is disabled")

        p = check_write_path(path)

        if not p.exists():
            return write_result(
                "denied",
                error_code="file_not_found",
                message=f"File does not exist, use safe_create_text_file first: {p}",
                retryable=False,
            )

        if p.is_dir():
            return write_result(
                "denied",
                error_code="is_directory",
                message=f"Refuse to rewrite directory: {p}",
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
        policy = load_policy()
        if not feature_enabled("replace_file", policy):
            return write_result("denied", error_code="feature_disabled", message="replace_file is disabled")

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
                message=f"Refuse to replace directory: {p}",
                retryable=False,
            )

        if old == "":
            return write_result(
                "denied",
                error_code="empty_old_text",
                message="old text must not be empty",
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
        policy = load_policy()
        if not feature_enabled("delete_file", policy):
            return write_result("denied", error_code="feature_disabled", message="delete_file is disabled")

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
def safe_read_text_file(path: str, max_chars: int = 12000, start_line: int | None = None, end_line: int | None = None) -> str:
    """
    Read a text file inside allowed roots.

    This is safer than exposing `cat`:
    - path is checked by allow_roots / deny_paths
    - output is truncated by max_chars
    - optional line range is supported
    """
    try:
        policy = load_policy()
        if not feature_enabled("read_file", policy):
            return write_result("denied", error_code="feature_disabled", message="read_file is disabled")

        p = check_read_path(path)

        if not p.exists():
            return write_result("denied", error_code="file_not_found", message=f"File does not exist: {p}")
        if not p.is_file():
            return write_result("denied", error_code="not_file", message=f"Path is not a file: {p}")

        max_chars = max(1, min(int(max_chars), int(policy.get("run_cmd", {}).get("max_stdout_chars", 12000))))
        text = p.read_text(encoding="utf-8", errors="replace")

        total_lines = None
        if start_line is not None or end_line is not None:
            lines = text.splitlines()
            total_lines = len(lines)
            s = 1 if start_line is None else max(1, int(start_line))
            e = total_lines if end_line is None else min(total_lines, int(end_line))
            if e < s:
                selected = []
            else:
                selected = lines[s - 1:e]
            text = "\n".join(selected)

        truncated = len(text) > max_chars
        if truncated:
            text = text[:max_chars]

        return write_result(
            "ok",
            action="read_text_file",
            path=str(p),
            chars=len(text),
            truncated=truncated,
            total_lines=total_lines,
            content=text,
        )

    except Exception as e:
        return write_result("error", error_type=type(e).__name__, message=str(e), retryable=False)


@mcp.tool()
def safe_list_dir(path: str = ".", max_entries: int = 200) -> str:
    """
    List one directory inside allowed roots.

    This is safer and more structured than shell `ls`.
    """
    try:
        policy = load_policy()
        if not feature_enabled("list_dir", policy):
            return write_result("denied", error_code="feature_disabled", message="list_dir is disabled")

        p = check_read_path(path)
        if not p.exists():
            return write_result("denied", error_code="path_not_found", message=f"Path does not exist: {p}")
        if not p.is_dir():
            return write_result("denied", error_code="not_directory", message=f"Path is not a directory: {p}")

        max_entries = max(1, min(int(max_entries), 1000))
        entries = []
        for child in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                st = child.stat()
                kind = "dir" if child.is_dir() else "file" if child.is_file() else "other"
                entries.append({
                    "name": child.name,
                    "path": str(child),
                    "type": kind,
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception as e:
                entries.append({"name": child.name, "path": str(child), "type": "unknown", "error": str(e)})

            if len(entries) >= max_entries:
                break

        return write_result(
            "ok",
            action="list_dir",
            path=str(p),
            entries=entries,
            truncated=len(entries) >= max_entries,
        )

    except Exception as e:
        return write_result("error", error_type=type(e).__name__, message=str(e), retryable=False)


@mcp.tool()
def safe_grep_text(pattern: str, path: str = ".", ignore_case: bool = False, recursive: bool = True, max_matches: int = 200) -> str:
    """
    Search text files inside allowed roots.

    This is a structured grep-like tool.
    For very large folders, use safe_readonly_cmd(cmd='grep', ...) if you prefer native grep speed.
    """
    try:
        policy = load_policy()
        if not feature_enabled("grep_text", policy):
            return write_result("denied", error_code="feature_disabled", message="grep_text is disabled")

        root = check_read_path(path)
        if not root.exists():
            return write_result("denied", error_code="path_not_found", message=f"Path does not exist: {root}")

        max_matches = max(1, min(int(max_matches), 2000))
        needle = pattern.lower() if ignore_case else pattern
        matches = []

        if root.is_file():
            files = [root]
        elif root.is_dir() and recursive:
            files = [p for p in root.rglob("*") if p.is_file()]
        elif root.is_dir():
            files = [p for p in root.iterdir() if p.is_file()]
        else:
            files = []

        for file_path in files:
            try:
                checked = check_read_path(file_path)
                # 双保险：跳过任何 .git 内部文件
                if any(part == ".git" for part in checked.parts):
                    continue
                text = checked.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for line_no, line in enumerate(text.splitlines(), start=1):
                hay = line.lower() if ignore_case else line
                if needle in hay:
                    matches.append({
                        "path": str(file_path),
                        "line": line_no,
                        "text": line,
                    })
                    if len(matches) >= max_matches:
                        return write_result(
                            "ok",
                            action="grep_text",
                            pattern=pattern,
                            path=str(root),
                            matches=matches,
                            truncated=True,
                        )

        return write_result(
            "ok",
            action="grep_text",
            pattern=pattern,
            path=str(root),
            matches=matches,
            truncated=False,
        )

    except Exception as e:
        return write_result("error", error_type=type(e).__name__, message=str(e), retryable=False)


@mcp.tool()
def safe_git_status(path: str = "") -> str:
    """
    Show local git status for an allowed workspace path.

    It may initialize a git repo inside the allow_root if none exists.
    This matches the sandbox design: git is the internal backup/history mechanism.
    """
    try:
        policy = load_policy()
        if not feature_enabled("git_status", policy):
            return write_result("denied", error_code="feature_disabled", message="git_status is disabled")

        if path:
            p = check_read_path(path)
        else:
            p = policy["allow_roots"][0]

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


@mcp.tool()
def safe_git_log(path: str = "", max_count: int = 20) -> str:
    """
    Show git commit history for the allowed workspace repo.
    """
    try:
        policy = load_policy()
        if not feature_enabled("git_log", policy):
            return write_result("denied", error_code="feature_disabled", message="git_log is disabled")

        if path:
            p = check_read_path(path)
        else:
            p = policy["allow_roots"][0]

        repo = ensure_repo(p)
        max_count = max(1, min(int(max_count), 100))
        r = run_git(["log", f"--max-count={max_count}", "--oneline", "--decorate"], repo)

        return write_result(
            "ok",
            action="git_log",
            repo=str(repo),
            stdout=r.stdout,
            stderr=r.stderr,
            returncode=r.returncode,
        )

    except Exception as e:
        return write_result("error", error_type=type(e).__name__, message=str(e), retryable=False)


@mcp.tool()
def safe_git_diff(path: str = "", ref: str = "HEAD") -> str:
    """
    Show git diff for the allowed workspace repo.

    Default: compare working tree against HEAD.
    If path is a file or dir, diff is limited to that path.
    """
    try:
        policy = load_policy()
        if not feature_enabled("git_diff", policy):
            return write_result("denied", error_code="feature_disabled", message="git_diff is disabled")

        ref = validate_commit_ref(ref)

        if path:
            p = check_read_path(path)
        else:
            p = policy["allow_roots"][0]

        repo = ensure_repo(p)
        args = ["diff", ref]

        if path:
            rel = p.relative_to(repo)
            args.extend(["--", str(rel)])

        r = run_git(args, repo)

        max_chars = int(policy.get("run_cmd", {}).get("max_stdout_chars", 12000))
        stdout = r.stdout[-max_chars:]
        stderr = r.stderr[-max_chars:]

        return write_result(
            "ok",
            action="git_diff",
            repo=str(repo),
            path=str(p),
            ref=ref,
            stdout_tail=stdout,
            stderr_tail=stderr,
            returncode=r.returncode,
        )

    except Exception as e:
        return write_result("error", error_type=type(e).__name__, message=str(e), retryable=False)


@mcp.tool()
def safe_run_python_entry(
    script_path: str,
    args: list[str] | None = None,
    timeout_sec: int | None = None,
) -> str:
    """
    Run a whitelisted Python entry script with argv-style args.

    This is a restricted execution interface:
    - It only runs Python scripts matched by run_python.allow_paths.
    - It refuses scripts matched by run_python.deny_paths.
    - It passes args as argv items with shell=False.
    - It does not accept arbitrary shell/cmd strings.
    - The script's own file access is NOT sandboxed here by design.
    """
    try:
        policy = load_policy()
        if not feature_enabled("run_python", policy):
            return write_result("denied", error_code="feature_disabled", message="run_python is disabled")

        run_policy = policy.get("run_python", {})

        if not run_policy.get("enabled", False):
            return write_result(
                "denied",
                error_code="run_python_disabled",
                message="run_python is disabled in policy",
                retryable=False,
            )

        python_bin_raw = str(run_policy.get("python_bin", "")).strip()
        if not python_bin_raw:
            python_bin_raw = sys.executable
        python_bin = Path(python_bin_raw).expanduser().resolve()

        cwd = Path(run_policy.get("cwd", str(policy["allow_roots"][0]))).expanduser().resolve()

        if not python_bin.exists() or not python_bin.is_file():
            return write_result(
                "denied",
                error_code="python_bin_not_found",
                message=f"python_bin does not exist or is not a file: {python_bin}",
                retryable=False,
            )

        allow_paths = resolve_policy_paths(run_policy.get("allow_paths", []))
        deny_paths = resolve_policy_paths(run_policy.get("deny_paths", []))

        max_timeout = int(run_policy.get("max_timeout_sec", 3600))
        max_stdout_chars = int(run_policy.get("max_stdout_chars", 12000))
        max_stderr_chars = int(run_policy.get("max_stderr_chars", 12000))
        max_args = int(run_policy.get("max_args", 64))
        max_arg_len = int(run_policy.get("max_arg_len", 1024))

        script = Path(script_path).expanduser().resolve()

        if script.suffix.lower() != ".py":
            return write_result(
                "denied",
                error_code="not_python_file",
                message=f"only .py files can be executed: {script}",
                retryable=False,
            )

        if not script.exists():
            return write_result(
                "denied",
                error_code="script_not_found",
                message=f"script not found: {script}",
                retryable=False,
            )

        if not script.is_file():
            return write_result(
                "denied",
                error_code="not_file",
                message=f"script is not a file: {script}",
                retryable=False,
            )

        if not allow_paths:
            return write_result(
                "denied",
                error_code="empty_run_allowlist",
                message="run_python.allow_paths is empty",
                retryable=False,
            )

        if not any(match_run_path(script, rule) for rule in allow_paths):
            return write_result(
                "denied",
                error_code="not_in_run_allowlist",
                message=f"script is not in run allowlist: {script}",
                retryable=False,
            )

        if any(match_run_path(script, rule) for rule in deny_paths):
            return write_result(
                "denied",
                error_code="in_run_denylist",
                message=f"script is in run denylist: {script}",
                retryable=False,
            )

        if not cwd.exists() or not cwd.is_dir():
            return write_result(
                "denied",
                error_code="bad_cwd",
                message=f"cwd does not exist or is not a directory: {cwd}",
                retryable=False,
            )

        safe_args = validate_run_args(args, max_args=max_args, max_arg_len=max_arg_len)

        if timeout_sec is None:
            timeout_sec = max_timeout
        timeout_sec = min(int(timeout_sec), max_timeout)
        if timeout_sec <= 0:
            return write_result(
                "denied",
                error_code="invalid_timeout",
                message="timeout_sec must be positive",
                retryable=False,
            )

        cmd = [str(python_bin), str(script), *safe_args]
        env = build_run_env(run_policy)

        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
            env=env,
        )

        return write_result(
            "ok",
            action="run_python_entry",
            script=str(script),
            cwd=str(cwd),
            args=safe_args,
            timeout_sec=timeout_sec,
            returncode=result.returncode,
            stdout_tail=result.stdout[-max_stdout_chars:],
            stderr_tail=result.stderr[-max_stderr_chars:],
            message="python entry finished",
        )

    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        return write_result(
            "error",
            error_code="timeout",
            message=f"process timeout after {timeout_sec} sec",
            stdout_tail=stdout[-4000:],
            stderr_tail=stderr[-4000:],
            retryable=True,
        )

    except Exception as e:
        return write_result(
            "error",
            error_type=type(e).__name__,
            message=str(e),
            retryable=False,
        )


@mcp.tool()
def safe_readonly_cmd(
    cmd: str,
    args: list[str] | None = None,
    cwd: str = "",
    timeout_sec: int | None = None,
) -> str:
    """
    Run a small whitelist of read-only commands.

    Supported by code:
    - ls
    - ll  -> internal alias for `ls -lah`
    - grep

    This is not a general shell:
    - cmd must be whitelisted by code and policy
    - args are argv items, never a shell string
    - shell=False
    - shell redirection/control tokens are rejected
    - path operands must stay inside allow_roots and outside deny_paths
    """
    try:
        policy = load_policy()
        if not feature_enabled("readonly_cmd", policy):
            return write_result("denied", error_code="feature_disabled", message="readonly_cmd is disabled")

        run_cmd = policy.get("run_cmd", {}) or {}

        if not run_cmd.get("enabled", False):
            return write_result(
                "denied",
                error_code="run_cmd_disabled",
                message="run_cmd is disabled in policy",
                retryable=False,
            )

        cmd = str(cmd or "").strip()
        if cmd not in CODE_ALLOWED_READONLY_CMDS:
            return write_result(
                "denied",
                error_code="cmd_not_allowed",
                message=f"command is not allowed by code: {cmd}",
                retryable=False,
            )

        cmd_cfg = get_run_cmd_config(policy, cmd)

        max_args = int(run_cmd.get("max_args", 64))
        max_arg_len = int(run_cmd.get("max_arg_len", 1024))
        max_timeout = int(run_cmd.get("max_timeout_sec", 10))
        max_stdout_chars = int(run_cmd.get("max_stdout_chars", 12000))
        max_stderr_chars = int(run_cmd.get("max_stderr_chars", 8000))

        safe_args = validate_cmd_args(args, max_args=max_args, max_arg_len=max_arg_len)

        if cwd:
            cwd_path = check_read_path(cwd)
        else:
            cwd_path = policy["allow_roots"][0]

        if not cwd_path.exists() or not cwd_path.is_dir():
            return write_result(
                "denied",
                error_code="bad_cwd",
                message=f"cwd does not exist or is not a directory: {cwd_path}",
                retryable=False,
            )

        if timeout_sec is None:
            timeout_sec = max_timeout
        timeout_sec = min(int(timeout_sec), max_timeout)
        if timeout_sec <= 0:
            return write_result(
                "denied",
                error_code="invalid_timeout",
                message="timeout_sec must be positive",
                retryable=False,
            )

        if cmd == "ll":
            bin_path = resolve_cmd_bin("ll", cmd_cfg)
            flags, paths = parse_ls_args(["-lah", *safe_args], cwd_path)
            final_cmd = [bin_path, "--color=never", *flags, "--", *paths]

        elif cmd == "ls":
            bin_path = resolve_cmd_bin("ls", cmd_cfg)
            flags, paths = parse_ls_args(safe_args, cwd_path)
            final_cmd = [bin_path, "--color=never", *flags, "--", *paths]

        elif cmd == "grep":
            bin_path = resolve_cmd_bin("grep", cmd_cfg)
            flags, pattern, paths = parse_grep_args(safe_args, cwd_path)
            base_flags = ["-I", "--binary-files=without-match", "--exclude-dir=.git"]
            final_cmd = [bin_path, *base_flags, *flags, "--", pattern, *paths]

        else:
            raise RuntimeError(f"unreachable command: {cmd}")

        result = subprocess.run(
            final_cmd,
            cwd=str(cwd_path),
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
            },
        )

        return write_result(
            "ok",
            action="readonly_cmd",
            cmd=cmd,
            cwd=str(cwd_path),
            args=safe_args,
            final_cmd=final_cmd,
            timeout_sec=timeout_sec,
            returncode=result.returncode,
            stdout_tail=result.stdout[-max_stdout_chars:],
            stderr_tail=result.stderr[-max_stderr_chars:],
            message="readonly command finished",
        )

    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        return write_result(
            "error",
            error_code="timeout",
            message=f"process timeout after {timeout_sec} sec",
            stdout_tail=stdout[-4000:],
            stderr_tail=stderr[-4000:],
            retryable=True,
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
