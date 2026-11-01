"""Evaluate commands and file accesses against built-in rules and a policy."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath

from .policy import Policy
from .shellparse import (SimpleCommand, long_flags, positionals, short_flags,
                         split_commands)

SEVERITY = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Finding:
    rule: str
    action: str
    reason: str
    segment: str = ""


@dataclass
class Decision:
    action: str
    findings: list[Finding]
    command: str = ""

    @property
    def reason(self) -> str:
        top = [f for f in self.findings if f.action == self.action]
        return "; ".join(f"{f.reason} [{f.rule}]" for f in top) or "no rule matched"

    def to_dict(self) -> dict:
        return {"action": self.action, "reason": self.reason, "command": self.command,
                "findings": [asdict(f) for f in self.findings]}


# --------------------------------------------------------------------------- #
# Rule catalogue: id -> (default action, description)
# --------------------------------------------------------------------------- #
RULES: dict[str, tuple[str, str]] = {
    "fs.rm-protected": ("deny", "recursive delete of /, home, the project root or a system directory"),
    "fs.rm-outside-project": ("ask", "recursive delete of a path outside the working directory"),
    "fs.write-system": ("ask", "agent file tools writing into system directories"),
    "fs.wipe-disk": ("deny", "mkfs / dd / wipefs / writes to raw block devices"),
    "fs.chmod-recursive": ("deny", "recursive chmod/chown on a protected path, or chmod -R 777"),
    "net.pipe-to-shell": ("deny", "piping a download straight into a shell or interpreter"),
    "git.force-push": ("deny", "force-push to a protected branch (other branches: ask)"),
    "git.discard-work": ("ask", "git reset --hard, clean -fd, checkout/restore ., stash clear, branch -D"),
    "git.rewrite-history": ("ask", "git filter-branch / filter-repo / push --mirror"),
    "db.destructive-sql": ("deny", "DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE, FLUSHALL"),
    "db.reset": ("deny", "framework database resets (prisma migrate reset, rails db:drop, ...)"),
    "cloud.destroy": ("ask", "terraform/pulumi destroy, kubectl delete, aws/gcloud/az deletes, docker prune"),
    "secrets.read": ("ask", "reading .env files, private keys and credential stores"),
    "secrets.env-dump": ("ask", "dumping all environment variables (printenv, env, export -p)"),
    "secrets.exfil": ("deny", "sending secret files or env dumps over the network"),
    "pkg.publish": ("ask", "publishing packages or images (npm publish, twine upload, docker push, ...)"),
    "sys.power": ("deny", "shutdown / reboot / kill -9 -1 / fork bombs"),
    "sys.persistence": ("ask", "editing shell rc files, authorized_keys or crontab"),
}

SYSTEM_DIRS = ["/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc",
               "/root", "/sbin", "/srv", "/sys", "/usr", "/var", "/Applications", "/Library",
               "/System", "/Users", "/Volumes", "/private"]

SECRET_GLOBS = [".env", ".env.*", "*.env", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", ".npmrc", ".pypirc", ".netrc",
                ".git-credentials", "credentials", "credentials.json", "service-account*.json",
                ".htpasswd", "secrets.yml", "secrets.yaml", "secrets.json", "*.tfvars", "*.tfstate",
                "kubeconfig"]
SECRET_PATH_PARTS = [".aws/credentials", ".aws/config", ".ssh/", ".kube/config", ".docker/config.json",
                     ".config/gcloud/", ".azure/", ".gnupg/"]
NOT_SECRET = re.compile(r"\.(example|sample|template|dist|tmpl)$|\.pub$", re.I)

READERS = {"cat", "less", "more", "head", "tail", "bat", "batcat", "nl", "strings", "xxd", "od",
           "hexdump", "base64", "grep", "rg", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq",
           "cp", "scp", "rsync", "tar", "zip", "openssl", "gpg", "source", ".", "vim", "vi", "nano",
           "emacs", "code", "jq", "yq", "python", "python3", "node", "diff", "tee", "type"}
NET_SENDERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "rsync", "ftp", "sftp",
               "http", "https", "xh", "telnet", "ssh"}
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby",
                "node", "php", "pwsh", "powershell", "iex"}
DOWNLOADERS = {"curl", "wget", "fetch", "http", "https", "xh", "aria2c", "iwr", "irm",
               "invoke-webrequest", "invoke-restmethod"}
RC_FILES = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish",
            ".ssh/authorized_keys", ".ssh/config", ".gitconfig"]


class Context:
    def __init__(self, policy: Policy, cwd: str | None = None, home: str | None = None):
        self.policy = policy
        self.cwd = os.path.normpath(cwd or os.getcwd())
        self.home = os.path.normpath(home or os.path.expanduser("~"))

    def resolve(self, path: str) -> str:
        p = path
        for var in ("$HOME", "${HOME}"):
            if p == var or p.startswith(var + "/"):
                p = self.home + p[len(var):]
        if p == "~" or p.startswith("~/"):
            p = self.home + p[1:]
        if not p.startswith("/"):
            p = os.path.join(self.cwd, p)
        return os.path.normpath(p)

    def protected(self) -> list[str]:
        extra = [self.resolve(p) for p in self.policy.protected_paths]
        return ["/", self.home, *SYSTEM_DIRS, *extra]

    def is_secret(self, path: str) -> bool:
        if not path or path.startswith("-"):
            return False
        p = path.lstrip("@<")
        if NOT_SECRET.search(p):
            return False
        name = PurePosixPath(p).name
        globs = SECRET_GLOBS + self.policy.secret_globs
        if any(fnmatch.fnmatch(name, g) for g in globs):
            return True
        if any(fnmatch.fnmatch(p, g) for g in self.policy.secret_globs):
            return True
        full = self.resolve(p)
        return any(part in full or full.endswith("/" + part.rstrip("/")) for part in SECRET_PATH_PARTS)


# --------------------------------------------------------------------------- #
# Individual checks. Each yields (rule_id, reason).
# --------------------------------------------------------------------------- #

def _check_rm(cmd: SimpleCommand, ctx: Context):
    if cmd.name not in ("rm", "rmdir", "shred", "unlink", "trash", "srm"):
        return
    flags, lflags = short_flags(cmd.args), long_flags(cmd.args)
    if "--no-preserve-root" in lflags:
        yield "fs.rm-protected", "rm --no-preserve-root"
        return
    recursive = bool({"r", "R"} & flags) or "--recursive" in lflags or cmd.name in ("shred", "srm")
    targets = positionals(cmd.args)
    for t in targets:
        if t in ("*", "/*", "~/*", "./*", ".*") or t.endswith("/*") and ctx.resolve(t[:-2]) in ctx.protected():
            if t in ("*", "./*", ".*") and ctx.cwd not in ctx.protected():
                if recursive:
                    yield "fs.rm-protected", f"recursive delete of everything in the project ({t})"
                continue
            yield "fs.rm-protected", f"wildcard delete of a protected directory ({t})"
            continue
        if "__SUBST__" in t or (t.startswith("$") and not t.startswith("$HOME")):
            if recursive:
                yield "fs.rm-outside-project", f"recursive delete of a dynamic path ({t}) that cannot be checked"
            continue
        full = ctx.resolve(t)
        if full in ctx.protected() or full == ctx.cwd or ctx.cwd.startswith(full.rstrip("/") + "/"):
            if recursive or full == "/":
                what = "the project root" if full == ctx.cwd else full
                yield "fs.rm-protected", f"recursive delete of {what}"
            continue
        inside_protected_sys = any(full.startswith(d + "/") for d in SYSTEM_DIRS if d not in ("/home", "/Users"))
        outside = not (full + "/").startswith(ctx.cwd.rstrip("/") + "/")
        if recursive and outside and not full.startswith(("/tmp/", "/var/tmp/", "/private/tmp/")):
            if inside_protected_sys and not full.startswith(ctx.home + "/"):
                yield "fs.rm-protected", f"recursive delete inside a system directory ({full})"
            else:
                yield "fs.rm-outside-project", f"recursive delete outside the project ({full})"


def _check_disk(cmd: SimpleCommand, ctx: Context):
    if cmd.name.startswith("mkfs") or cmd.name in ("wipefs", "fdisk", "sfdisk", "parted", "diskutil") and \
            any(a in ("eraseDisk", "zeroDisk", "partitionDisk") or a.startswith("/dev/") for a in cmd.args) \
            or cmd.name in ("wipefs", "mkswap"):
        yield "fs.wipe-disk", f"{cmd.name} can destroy a filesystem"
        return
    if cmd.name == "dd" and any(a.startswith("of=/dev/") and not a.startswith(("of=/dev/null", "of=/dev/stdout", "of=/dev/stderr")) for a in cmd.args):
        yield "fs.wipe-disk", "dd writing to a raw device"
    for op, target in cmd.extra.get("redirects", []):
        if op in (">", ">>") and re.match(r"/dev/(sd|nvme|hd|disk|mmcblk|vd|xvd)", target):
            yield "fs.wipe-disk", f"redirect into a block device ({target})"


def _check_chmod(cmd: SimpleCommand, ctx: Context):
    if cmd.name not in ("chmod", "chown", "chgrp"):
        return
    flags, lflags = short_flags(cmd.args), long_flags(cmd.args)
    if not ({"R"} & flags or "--recursive" in lflags):
        return
    pos = positionals(cmd.args)
    targets = pos[1:] if pos else []
    for t in targets:
        if ctx.resolve(t) in ctx.protected():
            yield "fs.chmod-recursive", f"recursive {cmd.name} on {ctx.resolve(t)}"
            return
    if cmd.name == "chmod" and pos and pos[0] in ("777", "0777", "a+rwx", "ugo+rwx"):
        yield "fs.chmod-recursive", "chmod -R 777 makes everything world-writable"


def _check_pipe_to_shell(cmd: SimpleCommand, ctx: Context):
    if cmd.name.lower() not in INTERPRETERS:
        return
    src = cmd.piped_from
    while src is not None:
        if src.name.lower() in DOWNLOADERS:
            yield "net.pipe-to-shell", f"{src.name} output piped into {cmd.name}"
            return
        src = src.piped_from


def _check_git(cmd: SimpleCommand, ctx: Context):
    if cmd.name != "git":
        return
    args = list(cmd.args)
    # skip global options like -C dir, -c k=v
    while args and args[0].startswith("-"):
        opt = args.pop(0)
        if opt in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") and args:
            args.pop(0)
    if not args:
        return
    sub, rest = args[0], args[1:]
    flags, lflags = short_flags(rest), long_flags(rest)
    pos = positionals(rest)
    if sub == "push":
        if "--mirror" in lflags:
            yield "git.rewrite-history", "git push --mirror overwrites every remote ref"
        refspecs = pos[1:]
        forced_refs = [r for r in refspecs if r.startswith("+")]
        force = "f" in flags or lflags & {"--force", "--force-with-lease", "--force-if-includes"} or forced_refs
        if force or "--delete" in lflags or "d" in flags:
            kind = "delete" if ("--delete" in lflags or "d" in flags) and not force else "force-push"
            targets = [r.lstrip("+").split(":")[-1].removeprefix("refs/heads/") for r in refspecs]
            protected = [t for t in targets if t in ctx.policy.protected_branches]
            if protected:
                yield "git.force-push", f"{kind} to protected branch {protected[0]}"
            elif not targets:
                yield "git.force-push", f"{kind} without an explicit branch (may hit a protected branch)"
            else:
                yield ("git.force-push@ask", f"{kind} to {', '.join(targets)}")
    elif sub == "reset" and "--hard" in lflags:
        yield "git.discard-work", "git reset --hard discards uncommitted work"
    elif sub == "clean" and "f" in flags and ({"d", "x", "X"} & flags):
        yield "git.discard-work", "git clean -fd deletes untracked files"
    elif sub in ("checkout", "restore") and any(p in (".", ":/", "*") for p in pos) and "--staged" not in lflags:
        yield "git.discard-work", f"git {sub} {' '.join(pos)} discards local changes"
    elif sub == "stash" and pos and pos[0] in ("clear", "drop"):
        yield "git.discard-work", f"git stash {pos[0]} deletes stashed work"
    elif sub == "branch" and ("D" in flags or ("d" in flags and "f" in flags)):
        yield "git.discard-work", "git branch -D deletes an unmerged branch"
    elif sub in ("filter-branch", "filter-repo"):
        yield "git.rewrite-history", f"git {sub} rewrites history"
    elif sub == "update-ref" and "d" in flags:
        yield "git.discard-work", "git update-ref -d deletes a ref"


SQL_PATTERNS = [
    (re.compile(r"\bdrop\s+(database|schema|table|collection|keyspace)\b", re.I), "DROP {0}"),
    (re.compile(r"\btruncate\s+(table\s+)?\w", re.I), "TRUNCATE"),
    (re.compile(r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*(;|$|\"|')(?![^;]*\bwhere\b)", re.I), "DELETE without WHERE"),
    (re.compile(r"\bflushall\b|\bflushdb\b", re.I), "Redis FLUSHALL/FLUSHDB"),
    (re.compile(r"\.dropDatabase\(\)|\bdropDatabase\b", re.I), "MongoDB dropDatabase"),
]
DB_RESET = [
    (("prisma", "migrate", "reset"), "prisma migrate reset"),
    (("prisma", "db", "push", "--force-reset"), "prisma db push --force-reset"),
    (("rails", "db:drop"), "rails db:drop"), (("rails", "db:reset"), "rails db:reset"),
    (("rake", "db:drop"), "rake db:drop"), (("rake", "db:reset"), "rake db:reset"),
    (("manage.py", "flush"), "django flush"), (("manage.py", "reset_db"), "django reset_db"),
    (("supabase", "db", "reset"), "supabase db reset"), (("dropdb",), "dropdb"),
    (("drizzle-kit", "drop"), "drizzle-kit drop"), (("sequelize", "db:drop"), "sequelize db:drop"),
    (("php", "artisan", "migrate:fresh"), "artisan migrate:fresh"), (("artisan", "db:wipe"), "artisan db:wipe"),
]


def _contains_seq(argv: list[str], seq: tuple[str, ...]) -> bool:
    names = [os.path.basename(a) for a in argv]
    it = iter(names)
    return all(any(s == n for n in it) for s in seq)


DB_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlite", "sqlcmd", "clickhouse-client", "clickhouse",
              "cockroach", "duckdb", "redis-cli", "valkey-cli", "mongosh", "mongo", "snowsql", "bq", "turso",
              "wrangler", "pgcli", "mycli", "litecli", "usql", "cqlsh", "influx", "spanner-cli"}


def _check_db(cmd: SimpleCommand, ctx: Context):
    names = {os.path.basename(a) for a in cmd.argv}
    is_db = bool(names & DB_CLIENTS) or _contains_seq(cmd.argv, ("prisma", "db", "execute"))
    text = " ".join(cmd.argv) if is_db else ""
    if is_db and cmd.piped_from is not None:  # echo "DROP TABLE x" | psql
        text += " " + " ".join(cmd.piped_from.argv)
    for regex, label in SQL_PATTERNS:
        m = regex.search(text)
        if m:
            yield "db.destructive-sql", label.format((m.group(1) or "").upper() if m.groups() else "")
            break
    for seq, label in DB_RESET:
        if _contains_seq(cmd.argv, seq):
            yield "db.reset", f"{label} wipes the database"
            break


CLOUD = [
    (("terraform", "destroy"), "terraform destroy"), (("terraform", "apply", "-destroy"), "terraform apply -destroy"),
    (("tofu", "destroy"), "tofu destroy"), (("pulumi", "destroy"), "pulumi destroy"),
    (("cdk", "destroy"), "cdk destroy"), (("helm", "uninstall"), "helm uninstall"),
    (("aws", "s3", "rb"), "aws s3 rb"), (("aws", "ec2", "terminate-instances"), "aws ec2 terminate-instances"),
    (("aws", "rds", "delete-db-instance"), "aws rds delete-db-instance"),
    (("aws", "rds", "delete-db-cluster"), "aws rds delete-db-cluster"),
    (("aws", "dynamodb", "delete-table"), "aws dynamodb delete-table"),
    (("aws", "cloudformation", "delete-stack"), "aws cloudformation delete-stack"),
    (("az", "group", "delete"), "az group delete"), (("fly", "apps", "destroy"), "fly apps destroy"),
    (("flyctl", "apps", "destroy"), "flyctl apps destroy"), (("heroku", "apps:destroy"), "heroku apps:destroy"),
    (("vercel", "remove"), "vercel remove"), (("docker", "system", "prune"), "docker system prune"),
    (("docker", "volume", "prune"), "docker volume prune"), (("docker", "volume", "rm"), "docker volume rm"),
    (("docker", "compose", "down", "-v"), "docker compose down -v"), (("docker-compose", "down", "-v"), "docker-compose down -v"),
    (("docker", "compose", "down", "--volumes"), "docker compose down --volumes"),
]


def _check_cloud(cmd: SimpleCommand, ctx: Context):
    for seq, label in CLOUD:
        if _contains_seq(cmd.argv, seq):
            yield "cloud.destroy", label
            return
    if cmd.name == "aws" and len(cmd.args) >= 2 and cmd.args[0] == "s3" and cmd.args[1] == "rm" and "--recursive" in cmd.args:
        yield "cloud.destroy", "aws s3 rm --recursive"
    elif cmd.name == "gcloud" and "delete" in cmd.args:
        yield "cloud.destroy", "gcloud ... delete"
    elif cmd.name in ("kubectl", "oc") and cmd.args and cmd.args[0] == "delete":
        pos = positionals(cmd.args[1:])
        if {"--all", "--all-namespaces"} & long_flags(cmd.args) or "A" in short_flags(cmd.args) or \
                (pos and pos[0] in ("namespace", "namespaces", "ns", "pv", "pvc", "node", "nodes", "crd")):
            yield "cloud.destroy", f"kubectl delete {' '.join(cmd.args[1:3])}"


def _check_secrets(cmd: SimpleCommand, ctx: Context):
    name = cmd.name
    if name in ("printenv", "env") and not cmd.args or name == "export" and cmd.args in (["-p"], []) \
            or name == "set" and not cmd.args or name == "declare" and cmd.args in (["-x"], ["-p"]):
        yield "secrets.env-dump", f"`{' '.join(cmd.argv)}` prints every secret in the environment"
    secret_args = [a for a in cmd.args if ctx.is_secret(a.split("=", 1)[-1])]
    for op, target in cmd.extra.get("redirects", []):
        if op in ("<",) and ctx.is_secret(target):
            secret_args.append(target)
    if name in NET_SENDERS:
        sending = [a for a in cmd.args if a.startswith("@") and ctx.is_secret(a[1:])]
        if name in ("scp", "rsync", "nc", "ncat", "netcat", "socat"):
            sending += secret_args
        if name == "curl":
            for i, a in enumerate(cmd.args[:-1]):
                if a in ("-T", "--upload-file", "-F", "--form") and ctx.is_secret(cmd.args[i + 1].split("@")[-1]):
                    sending.append(cmd.args[i + 1])
        if sending:
            yield "secrets.exfil", f"{name} uploads secret file {sending[0].lstrip('@')}"
            return
        src = cmd.piped_from
        while src is not None:
            if any(ctx.is_secret(a) for a in src.args) or src.name in ("printenv", "env") and not src.args:
                yield "secrets.exfil", f"secret data from `{src.raw}` piped into {name}"
                return
            src = src.piped_from
    if name in READERS and secret_args:
        yield "secrets.read", f"{name} reads secret file {secret_args[0]}"


def _check_publish(cmd: SimpleCommand, ctx: Context):
    for seq, label in [(("npm", "publish"), "npm publish"), (("pnpm", "publish"), "pnpm publish"),
                       (("yarn", "publish"), "yarn publish"), (("yarn", "npm", "publish"), "yarn npm publish"),
                       (("bun", "publish"), "bun publish"), (("twine", "upload"), "twine upload"),
                       (("poetry", "publish"), "poetry publish"), (("uv", "publish"), "uv publish"),
                       (("hatch", "publish"), "hatch publish"), (("flit", "publish"), "flit publish"),
                       (("cargo", "publish"), "cargo publish"), (("gem", "push"), "gem push"),
                       (("docker", "push"), "docker push"), (("podman", "push"), "podman push"),
                       (("gh", "release", "create"), "gh release create"), (("vsce", "publish"), "vsce publish")]:
        if _contains_seq(cmd.argv, seq) and cmd.argv[0].split("/")[-1] == seq[0] or \
                (seq[0] in ("npm", "pnpm", "yarn", "bun") and cmd.name == "npx" and _contains_seq(cmd.args, seq)):
            yield "pkg.publish", f"{label} publishes to a public registry"
            return


FORK_BOMB = re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")


def _check_sys(cmd: SimpleCommand, ctx: Context):
    if cmd.name in ("shutdown", "reboot", "halt", "poweroff", "init") and (cmd.name != "init" or cmd.args[:1] in (["0"], ["6"])):
        yield "sys.power", f"{cmd.name} stops the machine"
    elif cmd.name in ("kill", "pkill", "killall"):
        if cmd.name == "kill" and "-1" in cmd.args:
            yield "sys.power", "kill -1 terminates every process you own"
    elif cmd.name == "systemctl" and cmd.args[:1] in (["poweroff"], ["reboot"], ["halt"]):
        yield "sys.power", f"systemctl {cmd.args[0]}"
    for op, target in cmd.extra.get("redirects", []):
        full = ctx.resolve(target)
        if op in (">", ">>") and any(full == ctx.resolve("~/" + rc) for rc in RC_FILES):
            yield "sys.persistence", f"writes to {target}"
    if cmd.name == "tee" or cmd.name in ("cp", "mv", "ln", "install"):
        for t in positionals(cmd.args)[-1:] if cmd.name != "tee" else positionals(cmd.args):
            if any(ctx.resolve(t) == ctx.resolve("~/" + rc) for rc in RC_FILES):
                yield "sys.persistence", f"{cmd.name} overwrites {t}"
    if cmd.name == "crontab" and ({"r", "e"} & short_flags(cmd.args) or positionals(cmd.args)):
        yield "sys.persistence", "modifies the user crontab"


CHECKS = [_check_rm, _check_disk, _check_chmod, _check_pipe_to_shell, _check_git, _check_db,
          _check_cloud, _check_secrets, _check_publish, _check_sys]


def _combine(findings: list[Finding], command: str) -> Decision:
    action = "allow"
    for f in findings:
        if SEVERITY[f.action] > SEVERITY[action]:
            action = f.action
    return Decision(action=action, findings=findings, command=command)


def _apply(policy: Policy, rule: str, reason: str, segment: str) -> Finding | None:
    """Turn a raw rule hit into a Finding, honouring policy overrides.

    A rule id may carry a softer level, e.g. ``git.force-push@ask`` for a force
    push to a non-protected branch; user overrides of the rule still win.
    """
    forced = None
    if "@" in rule:
        rule, forced = rule.split("@", 1)
    default = RULES[rule][0]
    if forced and SEVERITY[forced] < SEVERITY[default]:
        default = forced
    action = policy.action_for(rule, default)
    if action is None or action == "allow":
        return None
    return Finding(rule, action, reason, segment)


def evaluate_command(command: str, policy: Policy | None = None, cwd: str | None = None,
                     home: str | None = None) -> Decision:
    """Decide whether a shell command line should be allowed, asked about or denied."""
    policy = policy or Policy()
    ctx = Context(policy, cwd=cwd, home=home)
    findings: list[Finding] = []
    if FORK_BOMB.search(command):
        f = _apply(policy, "sys.power", "fork bomb", command)
        if f:
            findings.append(f)
    if re.search(r"\b(bash|sh|zsh|source|\.)\s+<\(\s*(curl|wget)\b", command):
        f = _apply(policy, "net.pipe-to-shell", "shell executing a download via process substitution", command)
        if f:
            findings.append(f)
    if re.search(r"\b(iex|invoke-expression)\b.*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b", command, re.I) or \
            re.search(r"\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*iex\b", command, re.I):
        f = _apply(policy, "net.pipe-to-shell", "PowerShell download piped into Invoke-Expression", command)
        if f:
            findings.append(f)
    for cmd in split_commands(command):
        if any(p.search(cmd.raw) for p in policy.allow_patterns):
            continue
        for check in CHECKS:
            for rule, reason in check(cmd, ctx):
                f = _apply(policy, rule, reason, cmd.raw)
                if f:
                    findings.append(f)
    for c in policy.custom:
        if c.pattern.search(command):
            findings.append(Finding(c.id, c.action, c.reason, command))
    findings = [f for f in findings if f.action != "allow"]
    # de-duplicate (nested shells can report the same thing twice)
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.reason)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return _combine(unique, command)


def evaluate_path(path: str, mode: str = "read", policy: Policy | None = None, cwd: str | None = None,
                  home: str | None = None) -> Decision:
    """Decide on a file read/write performed by an agent's built-in file tools."""
    policy = policy or Policy()
    ctx = Context(policy, cwd=cwd, home=home)
    findings: list[Finding] = []
    if ctx.is_secret(path):
        f = _apply(policy, "secrets.read", f"agent wants to {mode} secret file {path}", path)
        if f:
            findings.append(f)
    if mode == "write":
        full = ctx.resolve(path)
        if any(full == ctx.resolve("~/" + rc) for rc in RC_FILES):
            f = _apply(policy, "sys.persistence", f"agent wants to modify {path}", path)
            if f:
                findings.append(f)
        elif any(full == d or full.startswith(d + "/") for d in SYSTEM_DIRS
                 if d not in ("/home", "/Users", "/private")) and not full.startswith(ctx.home + "/"):
            f = _apply(policy, "fs.write-system", f"agent wants to write system file {full}", path)
            if f:
                findings.append(f)
    for c in policy.custom:
        if c.pattern.search(path):
            findings.append(Finding(c.id, c.action, c.reason, path))
    return _combine([f for f in findings if f.action != "allow"], path)
