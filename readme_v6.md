
我按你这套“**不防心坏，只防发疯**”的设计理念，整理成了一个完整文件，并且已经做过 `py_compile` 语法检查。

我是基于你贴的这版 `safe_workspace` 改的：

文件: server_v6_chatgpt_create.py
policy 示例: safe_workspace_policy_v6.json
主要调整如下：

1. **保留你的 git 逻辑**

   我没有再把 `safe_git_status` 改成纯只读。
   它仍然允许 `ensure_repo()` 在 allow root 内初始化 git，因为这符合你的核心设计：沙箱内文件修改都应该被 git history 接管。

2. **加了代码级功能开关**

   文件顶部有：

```python
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
```

这里关掉后，policy 不能重新打开。
policy 里的 `features` 只能做第二层“软关闭”。

3. **新增了查询工具**

新增：

```python
safe_read_text_file(...)
safe_list_dir(...)
safe_grep_text(...)
safe_readonly_cmd(...)
safe_git_log(...)
safe_git_diff(...)
```

其中 `safe_readonly_cmd` 只支持：

```text
ls
ll
grep
```

`ll` 是内部别名，相当于：

```bash
ls -lah
```

不是开放 shell alias。

4. **没有开放任意 cmd 字符串**

也就是说没有这种危险接口：

```python
safe_run_cmd("ls && rm -rf xxx")
```

而是：

```python
safe_readonly_cmd(
    cmd="ll",
    args=["."],
    cwd="/media/totem_disk/totem/jizheng/workspace_2026/agent_learn/sand_box",
)
```

内部用的是：

```python
subprocess.run(..., shell=False)
```

并且会拒绝：

```text
>
>>
|
&&
;
2>
&>
```

这类 shell 控制符。

5. **Python 执行逻辑保持你的设定**

`safe_run_python_entry` 仍然只限制“入口脚本本身”必须在 `run_python.allow_paths` 里。

但脚本内部读写沙箱外文件，MCP 层不拦。
这个符合你说的第 3 点：你现在的工作模式确实需要白名单 Python 脚本去处理沙箱外数据。

6. **修了一个小坑**

`safe_replace_text_file` 现在会拒绝 `old == ""`。
否则空字符串 replace 是非常容易让弱智 Agent 把整个文件搞爆炸的操作。

---

你本地替换时大概这样：

```bash
cp safe_workspace_server_v2.py /你的/mcp/server/目录/server.py
cp safe_workspace_policy_example_v2.json /你的/mcp/server/目录/safe_workspace_policy.json
```

然后把 policy 里的：

```json
"allow_roots": [
  "/media/totem_disk/totem/jizheng/workspace_2026/agent_learn/sand_box"
]
```

改成你的真实沙箱路径即可。

如果你已有 policy，不要直接覆盖也行，把新示例里的 `features` 和 `run_cmd` 两段合进去就可以。
