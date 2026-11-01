"""Adapters between agentfence decisions and agent hook protocols."""

from __future__ import annotations

import datetime as _dt
import json
import os

from .engine import Decision, evaluate_command, evaluate_path
from .policy import Policy

CLAUDE_FILE_TOOLS = {"Read": "read", "Write": "write", "Edit": "write", "MultiEdit": "write",
                     "NotebookEdit": "write", "NotebookRead": "read"}
CURSOR_SHELL_TOOLS = {"Shell", "Bash", "run_terminal_cmd", "Terminal"}
CURSOR_FILE_TOOLS = {"Read": "read", "Write": "write", "Delete": "write", "Edit": "write"}


def _log(policy: Policy, decision: Decision, source: str, cwd: str) -> None:
    if not policy.log_file or decision.action == "allow":
        return
    path = policy.log_file
    if not os.path.isabs(path):
        base = os.path.dirname(policy.source) if policy.source else cwd
        path = os.path.join(base, path)
    entry = {"time": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
             "source": source, **decision.to_dict()}
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _message(decision: Decision) -> str:
    verb = "blocked" if decision.action == "deny" else "needs approval"
    return f"agentfence {verb}: {decision.reason}"


def handle_claude(payload: dict, policy: Policy, home: str | None = None) -> dict | None:
    """Claude Code PreToolUse hook. Returns JSON to print, or None to stay silent.

    Staying silent on "allow" keeps Claude Code's normal permission flow intact
    instead of auto-approving commands.
    """
    tool = payload.get("tool_name", "")
    tin = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    if tool == "Bash" and isinstance(tin.get("command"), str):
        decision = evaluate_command(tin["command"], policy, cwd=cwd, home=home)
    elif tool in CLAUDE_FILE_TOOLS and (tin.get("file_path") or tin.get("notebook_path")):
        decision = evaluate_path(tin.get("file_path") or tin.get("notebook_path"),
                                 CLAUDE_FILE_TOOLS[tool], policy, cwd=cwd, home=home)
    else:
        return None
    _log(policy, decision, f"claude:{tool}", cwd)
    if decision.action == "allow":
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision.action,
                                   "permissionDecisionReason": _message(decision)}}


def handle_cursor(payload: dict, policy: Policy, home: str | None = None) -> dict:
    """Cursor hooks: beforeShellExecution, beforeReadFile and preToolUse.

    Cursor requires a JSON answer from permission hooks, so this always returns one.
    """
    event = payload.get("hook_event_name", "")
    cwd = payload.get("cwd") or (payload.get("workspace_roots") or [None])[0] or os.getcwd()
    file_hook = False
    if event == "preToolUse" or ("tool_name" in payload and "tool_input" in payload and event != "beforeMCPExecution"):
        tool = payload.get("tool_name", "")
        tin = payload.get("tool_input") or {}
        if isinstance(tin, str):
            try:
                tin = json.loads(tin)
            except ValueError:
                tin = {}
        cwd = tin.get("working_directory") or cwd
        if tool in CURSOR_SHELL_TOOLS and isinstance(tin.get("command"), str):
            decision = evaluate_command(tin["command"], policy, cwd=cwd, home=home)
        elif tool in CURSOR_FILE_TOOLS and (tin.get("file_path") or tin.get("path")):
            decision = evaluate_path(tin.get("file_path") or tin.get("path"), CURSOR_FILE_TOOLS[tool],
                                     policy, cwd=cwd, home=home)
            file_hook = True
        else:
            return {"permission": "allow"}
    elif isinstance(payload.get("command"), str) and event != "beforeMCPExecution":
        decision = evaluate_command(payload["command"], policy, cwd=cwd, home=home)
    elif payload.get("file_path") and event in ("beforeReadFile", "beforeTabFileRead", ""):
        decision = evaluate_path(payload["file_path"], "read", policy, cwd=cwd, home=home)
        file_hook = True
    else:
        return {"permission": "allow"}
    _log(policy, decision, f"cursor:{event or 'unknown'}", cwd)
    if decision.action == "allow":
        return {"permission": "allow"}
    action = decision.action
    if action == "ask" and (file_hook or event == "preToolUse"):
        action = "deny"  # these hooks only enforce allow/deny
    msg = _message(decision)
    return {"permission": action, "user_message": msg,
            "agent_message": msg + ". Do not try to work around this; ask the user instead."}
