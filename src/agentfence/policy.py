"""Policy loading. Policies are TOML files (stdlib ``tomllib``, no deps)."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = ("allow", "ask", "deny")
POLICY_FILENAMES = (".agentfence.toml", "agentfence.toml")


class PolicyError(ValueError):
    pass


@dataclass
class CustomRule:
    id: str
    pattern: re.Pattern
    action: str
    reason: str


@dataclass
class Policy:
    """Effective policy. Defaults are safe for any repo without configuration."""

    protected_branches: list[str] = field(default_factory=lambda: ["main", "master", "production", "prod", "release"])
    protected_paths: list[str] = field(default_factory=list)
    secret_globs: list[str] = field(default_factory=list)
    rule_overrides: dict[str, str] = field(default_factory=dict)  # rule id -> action|"off"
    custom: list[CustomRule] = field(default_factory=list)
    allow_patterns: list[re.Pattern] = field(default_factory=list)
    log_file: str | None = None
    source: str | None = None

    def action_for(self, rule_id: str, default: str) -> str | None:
        """Return the configured action for a rule, or None when disabled."""
        override = self.rule_overrides.get(rule_id)
        if override is None:
            # allow prefix overrides such as "git" = "allow"
            prefix = rule_id.split(".", 1)[0]
            override = self.rule_overrides.get(prefix)
        if override is None:
            return default
        if override == "off":
            return None
        return override


def _validate_action(value: str, where: str, allow_off: bool = False) -> str:
    valid = ACTIONS + (("off",) if allow_off else ())
    if value not in valid:
        raise PolicyError(f"{where}: action must be one of {', '.join(valid)} (got {value!r})")
    return value


def parse_policy(data: dict, source: str | None = None) -> Policy:
    pol = Policy(source=source)
    settings = data.get("settings", {})
    if "protected_branches" in settings:
        pol.protected_branches = [str(b) for b in settings["protected_branches"]]
    pol.protected_paths = [str(p) for p in settings.get("protected_paths", [])]
    pol.secret_globs = [str(p) for p in settings.get("secret_files", [])]
    pol.log_file = settings.get("log_file")
    for rid, action in data.get("rules", {}).items():
        pol.rule_overrides[rid] = _validate_action(str(action), f"[rules] {rid}", allow_off=True)
    for i, item in enumerate(data.get("custom", [])):
        try:
            pattern = re.compile(item["pattern"])
        except KeyError:
            raise PolicyError(f"[[custom]] #{i + 1}: missing 'pattern'") from None
        except re.error as exc:
            raise PolicyError(f"[[custom]] #{i + 1}: bad regex: {exc}") from None
        pol.custom.append(CustomRule(
            id=f"custom.{item.get('id', i + 1)}",
            pattern=pattern,
            action=_validate_action(item.get("action", "deny"), f"[[custom]] #{i + 1}"),
            reason=item.get("reason", "matched a custom policy rule"),
        ))
    for i, item in enumerate(data.get("allow", [])):
        pat = item["pattern"] if isinstance(item, dict) else item
        try:
            pol.allow_patterns.append(re.compile(pat))
        except re.error as exc:
            raise PolicyError(f"[[allow]] #{i + 1}: bad regex: {exc}") from None
    return pol


def find_policy_file(start: str | os.PathLike | None = None) -> Path | None:
    """Look for a policy in start and its parents, then in the user config dir."""
    env = os.environ.get("AGENTFENCE_POLICY")
    if env:
        return Path(env)
    here = Path(start or os.getcwd()).resolve()
    for d in (here, *here.parents):
        for name in POLICY_FILENAMES:
            p = d / name
            if p.is_file():
                return p
        if (d / ".git").exists():
            break
    cfg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "agentfence" / "policy.toml"
    return cfg if cfg.is_file() else None


def load_policy(path: str | os.PathLike | None = None, cwd: str | None = None) -> Policy:
    p = Path(path) if path else find_policy_file(cwd)
    if p is None:
        return Policy()
    try:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{p}: {exc}") from None
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {p}") from None
    return parse_policy(data, source=str(p))


DEFAULT_POLICY_TOML = '''# agentfence policy - https://github.com/hamarshehmhmd/agentfence
# Actions: "allow", "ask" (require a human), "deny" (block), "off" (disable rule).

[settings]
protected_branches = ["main", "master", "production"]
# Extra paths an agent must never delete or chmod recursively.
protected_paths = []
# Extra secret files (glob patterns) on top of the built-in list (.env, keys, ...).
secret_files = []
# Append every ask/deny decision to this JSONL file (relative to the repo).
# log_file = ".agentfence.log"

[rules]
# Override built-in rules by id (see `agentfence rules`), or a whole group:
# "git.discard-work" = "allow"
# "pkg" = "deny"

# Your own regex rules, matched against the full command line.
# [[custom]]
# id = "prod-db"
# pattern = "psql .*prod"
# action = "deny"
# reason = "Agents may not connect to the production database"

# Commands matching these regexes are always allowed.
# [[allow]]
# pattern = "^rm -rf (dist|build|node_modules)$"
'''
