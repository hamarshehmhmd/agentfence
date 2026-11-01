"""Command line interface: check, hook, init, install, rules."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .engine import RULES, evaluate_command, evaluate_path
from .hooks import handle_claude, handle_cursor
from .policy import DEFAULT_POLICY_TOML, PolicyError, load_policy

EXIT = {"allow": 0, "ask": 1, "deny": 2}
COLORS = {"allow": "\033[32m", "ask": "\033[33m", "deny": "\033[31m"}
ICONS = {"allow": "ALLOW", "ask": "ASK  ", "deny": "DENY "}


def _color(action: str, text: str, enabled: bool) -> str:
    return f"{COLORS[action]}\033[1m{text}\033[0m" if enabled else text


def cmd_check(args) -> int:
    policy = load_policy(args.policy, cwd=args.cwd)
    commands = [" ".join(args.command)] if args.command else [line.rstrip("\n") for line in sys.stdin if line.strip()]
    worst = "allow"
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR") or args.color
    results = []
    for c in commands:
        d = evaluate_path(c, args.file_mode, policy, cwd=args.cwd) if args.file else \
            evaluate_command(c, policy, cwd=args.cwd)
        results.append(d)
        if EXIT[d.action] > EXIT[worst]:
            worst = d.action
    if args.json:
        out = [d.to_dict() for d in results]
        print(json.dumps(out[0] if len(out) == 1 else out, indent=2))
    else:
        for d in results:
            print(f"{_color(d.action, ICONS[d.action], color)}  {d.command}")
            for f in d.findings:
                print(f"       -> {f.reason} [{f.rule}: {f.action}]")
    return EXIT[worst]


def cmd_hook(args) -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    cwd = payload.get("cwd") or (payload.get("workspace_roots") or [None])[0]
    try:
        policy = load_policy(args.policy, cwd=cwd)
    except PolicyError as exc:
        # fail closed with an explanation rather than silently allowing
        msg = f"agentfence policy error: {exc}"
        if args.agent == "claude":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                     "permissionDecisionReason": msg}}))
        else:
            print(json.dumps({"permission": "ask", "user_message": msg, "agent_message": msg}))
        return 0
    if args.agent == "claude":
        out = handle_claude(payload, policy)
        if out:
            print(json.dumps(out))
    else:
        print(json.dumps(handle_cursor(payload, policy)))
    return 0


def cmd_init(args) -> int:
    path = os.path.join(args.dir, ".agentfence.toml")
    if os.path.exists(path) and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DEFAULT_POLICY_TOML)
    print(f"wrote {path}")
    return 0


def _merge_json(path: str, mutate) -> None:
    data = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
        data = json.loads(text) if text else {}
    mutate(data)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def cmd_install(args) -> int:
    base = os.path.expanduser("~") if args.user else args.dir
    exe = args.exe
    if args.agent == "claude":
        path = os.path.join(base, ".claude", "settings.json")
        command = f"{exe} hook claude"

        def mutate(d):
            pre = d.setdefault("hooks", {}).setdefault("PreToolUse", [])
            for entry in pre:
                if any(h.get("command") == command for h in entry.get("hooks", [])):
                    return
            pre.append({"matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit",
                        "hooks": [{"type": "command", "command": command}]})
    else:
        path = os.path.join(base, ".cursor", "hooks.json")
        command = f"{exe} hook cursor"

        def mutate(d):
            d.setdefault("version", 1)
            hooks = d.setdefault("hooks", {})
            for event in ("beforeShellExecution", "beforeReadFile"):
                lst = hooks.setdefault(event, [])
                if not any(h.get("command") == command for h in lst):
                    lst.append({"command": command})
    _merge_json(path, mutate)
    print(f"installed agentfence hook for {args.agent} in {path}")
    return 0


def cmd_rules(args) -> int:
    width = max(len(r) for r in RULES)
    for rid, (action, desc) in RULES.items():
        print(f"{rid.ljust(width)}  {action.ljust(5)}  {desc}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentfence", description="Policy firewall for AI coding agents' shell commands.")
    p.add_argument("--version", action="version", version=f"agentfence {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="evaluate a command (or one per stdin line); exit 0 allow, 1 ask, 2 deny")
    c.add_argument("command", nargs=argparse.REMAINDER)
    c.add_argument("--policy")
    c.add_argument("--cwd", default=None)
    c.add_argument("--json", action="store_true")
    c.add_argument("--color", action="store_true", help="force colored output")
    c.add_argument("--file", action="store_true", help="treat the argument as a file path an agent wants to access")
    c.add_argument("--file-mode", choices=("read", "write"), default="read")
    c.set_defaults(func=cmd_check)

    h = sub.add_parser("hook", help="run as an agent hook (reads JSON on stdin)")
    h.add_argument("agent", choices=("claude", "cursor"))
    h.add_argument("--policy")
    h.set_defaults(func=cmd_hook)

    i = sub.add_parser("init", help="write a starter .agentfence.toml")
    i.add_argument("--dir", default=".")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    ins = sub.add_parser("install", help="register the hook in .claude/settings.json or .cursor/hooks.json")
    ins.add_argument("agent", choices=("claude", "cursor"))
    ins.add_argument("--dir", default=".")
    ins.add_argument("--user", action="store_true", help="install in your home directory instead of the project")
    ins.add_argument("--exe", default="agentfence", help="command used to invoke agentfence")
    ins.set_defaults(func=cmd_install)

    r = sub.add_parser("rules", help="list built-in rules and their default actions")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
