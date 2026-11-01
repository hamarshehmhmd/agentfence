"""Split a shell command line into simple commands.

This is deliberately conservative: it is not a full POSIX shell parser, but it
understands the constructs agents actually use to chain or hide commands:
``;``, ``&&``, ``||``, ``|``, ``&``, newlines, ``$(...)``, backticks,
``bash -c "..."`` / ``sh -c``, ``eval``, ``xargs`` and wrapper commands such as
``sudo``, ``env``, ``nohup``, ``time`` and ``timeout``.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

OPERATORS = ("&&", "||", ";;", ";", "|&", "|", "&", "\n")

# Wrappers whose first non-option argument is the real command.
WRAPPERS = {"sudo", "doas", "nohup", "time", "nice", "ionice", "command",
            "builtin", "exec", "stdbuf", "unbuffer", "caffeinate"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}


@dataclass
class SimpleCommand:
    """One command with its arguments, plus whether it receives piped input."""

    argv: list[str]
    piped_from: "SimpleCommand | None" = None
    raw: str = ""
    sudo: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return os.path.basename(self.argv[0]) if self.argv else ""

    @property
    def args(self) -> list[str]:
        return self.argv[1:]


def _extract_substitutions(text: str) -> tuple[str, list[str]]:
    """Return text with $(...) and `...` bodies pulled out as separate scripts."""
    subs: list[str] = []
    out = []
    i = 0
    in_single = False
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_single:
            # skip single-quoted literal entirely
            j = text.find("'", i + 1)
            if j == -1:
                out.append(text[i:])
                break
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == "$" and text[i + 1:i + 2] == "(" and text[i + 2:i + 3] != "(":
            depth = 1
            j = i + 2
            while j < len(text) and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            subs.append(text[i + 2:j - 1])
            out.append("__SUBST__")
            i = j
            continue
        if ch == "`":
            j = text.find("`", i + 1)
            if j == -1:
                j = len(text)
            subs.append(text[i + 1:j])
            out.append("__SUBST__")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), subs


_DUP_REDIR = re.compile(r"(\d*)(>&|<&)(\d+|-)")


def _tokenize(text: str) -> list[str]:
    text = _DUP_REDIR.sub(" ", text)          # 2>&1, >&2, <&0
    text = text.replace("&>>", ">>").replace("&>", ">")
    text = text.replace("\n", " ; ")
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|")
    lex.whitespace_split = True
    lex.commenters = "#"
    try:
        return list(lex)
    except ValueError:
        # unbalanced quotes: fall back to a crude split so we still inspect it
        return text.split()


_REDIR = re.compile(r"^(\d*)(>>|>|<<<|<<|<)(.*)$")


def _split_redirects(argv: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Remove redirections from argv, returning (argv, [(op, target), ...])."""
    out: list[str] = []
    redirs: list[tuple[str, str]] = []
    i = 0
    while i < len(argv):
        m = _REDIR.match(argv[i])
        if m:
            op, target = m.group(2), m.group(3)
            if not target and i + 1 < len(argv):
                target = argv[i + 1]
                i += 1
            redirs.append((op, target))
        else:
            out.append(argv[i])
        i += 1
    return out, redirs


def _strip_wrappers(argv: list[str]) -> tuple[list[str], bool]:
    sudo = False
    changed = True
    while argv and changed:
        changed = False
        name = os.path.basename(argv[0])
        # leading VAR=value assignments
        if "=" in argv[0] and not argv[0].startswith("=") and argv[0].split("=", 1)[0].isidentifier():
            argv = argv[1:]
            changed = True
            continue
        if name in WRAPPERS:
            if name in ("sudo", "doas"):
                sudo = True
            argv = argv[1:]
            # drop wrapper options (and the value of sudo -u USER)
            while argv and argv[0].startswith("-"):
                opt = argv[0]
                argv = argv[1:]
                if opt in ("-u", "-g", "-n") and name in ("sudo", "doas", "nice") and argv:
                    argv = argv[1:]
            changed = True
            continue
        if name == "env":
            rest = argv[1:]
            while rest and (rest[0].startswith("-") or ("=" in rest[0] and rest[0].split("=", 1)[0].isidentifier())):
                rest = rest[1:]
            if not rest:  # bare `env` prints the environment: keep it visible
                return ["env"], sudo
            argv = rest
            changed = True
            continue
        if name == "timeout":
            argv = argv[1:]
            while argv and argv[0].startswith("-"):
                argv = argv[1:]
            if argv:  # duration
                argv = argv[1:]
            changed = True
            continue
    return argv, sudo


def split_commands(text: str, _depth: int = 0) -> list[SimpleCommand]:
    """Flatten a command line into SimpleCommands, recursing into nested shells."""
    if _depth > 5 or not text.strip():
        return []
    body, subs = _extract_substitutions(text)
    result: list[SimpleCommand] = []
    for sub in subs:
        result.extend(split_commands(sub, _depth + 1))

    tokens = _tokenize(body)
    segments: list[tuple[list[str], str | None]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok in OPERATORS or (tok and set(tok) <= set(";&|")):
            segments.append((cur, tok))
            cur = []
        else:
            cur.append(tok)
    segments.append((cur, None))

    prev: SimpleCommand | None = None
    prev_op: str | None = None
    for argv, op in segments:
        argv, redirs = _split_redirects(argv)
        argv, sudo = _strip_wrappers(argv)
        if not argv:
            if redirs:  # bare redirection such as `> file`
                result.append(SimpleCommand(argv=[":"], raw="", extra={"redirects": redirs}))
            prev, prev_op = None, op
            continue
        cmd = SimpleCommand(argv=argv, sudo=sudo, raw=" ".join(argv),
                            extra={"redirects": redirs})
        if prev is not None and prev_op in ("|", "|&"):
            cmd.piped_from = prev
        nested = _nested_script(cmd)
        if nested is not None:
            inner = split_commands(nested, _depth + 1)
            for c in inner:
                c.sudo = c.sudo or sudo
            if inner and cmd.piped_from is not None and inner[0].piped_from is None:
                inner[0].piped_from = cmd.piped_from
            result.extend(inner)
            # keep the outer command too (e.g. so `curl | bash` is visible)
            result.append(cmd)
        else:
            result.append(cmd)
        if cmd.name == "xargs":
            inner_argv = [a for a in cmd.args if not a.startswith("-")]
            if inner_argv:
                x = SimpleCommand(argv=inner_argv, raw=" ".join(inner_argv), sudo=sudo)
                x.piped_from = cmd.piped_from
                result.append(x)
        prev, prev_op = cmd, op
    return result


def _nested_script(cmd: SimpleCommand) -> str | None:
    if cmd.name in SHELLS:
        args = cmd.args
        for i, a in enumerate(args):
            if a.startswith("-") and "c" in a.lstrip("-") and not a.startswith("--"):
                return args[i + 1] if i + 1 < len(args) else ""
        return None
    if cmd.name == "eval":
        return " ".join(cmd.args)
    return None


def short_flags(args: list[str]) -> set[str]:
    """Collect single-letter flags from clustered short options (-rf -> {r,f})."""
    flags: set[str] = set()
    for a in args:
        if a == "--":
            break
        if a.startswith("-") and not a.startswith("--") and len(a) > 1:
            flags.update(a[1:])
    return flags


def long_flags(args: list[str]) -> set[str]:
    return {a.split("=", 1)[0] for a in args if a.startswith("--") and a != "--"}


def positionals(args: list[str]) -> list[str]:
    out = []
    after_dd = False
    for a in args:
        if after_dd:
            out.append(a)
        elif a == "--":
            after_dd = True
        elif not a.startswith("-") or a == "-":
            out.append(a)
    return out


def quote(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
