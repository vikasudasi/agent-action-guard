"""Deterministic dangerous-action signature rule engine."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml

from guard.decision import Decision, Verdict
from guard.schema import Action

RuleSeverity = Literal["block", "warn"]

EXFIL_DOMAIN_PATTERNS: tuple[str, ...] = (
    "pastebin.com",
    "pastie.org",
    "transfer.sh",
    "webhook.site",
    "0x0.st",
    "dpaste.org",
    "hastebin.com",
    "ghostbin.com",
    "requestbin.com",
    "pipedream.net",
    "hooks.slack.com",
    "discord.com/api/webhooks",
    "ngrok.io",
)

CREDENTIAL_PATH_MARKERS: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/passwd",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".pem",
    ".key",
    "id_rsa",
    "id_ed25519",
    "secrets",
    "credentials.json",
    ".netrc",
)

CREDENTIAL_DIR_MARKERS: tuple[str, ...] = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
)

SYSTEM_DIR_MARKERS: tuple[str, ...] = (
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/var/log/",
    "/boot/",
    "/sys/",
    "/proc/",
)

WEBHOOK_HOST_MARKERS: tuple[str, ...] = (
    "webhook",
    "callback",
    "hook",
    "requestbin",
    "pipedream",
    "hooks.slack.com",
    "discord.com/api/webhooks",
)

MCP_DANGEROUS_TOOL_PATTERNS: tuple[tuple[str, RuleSeverity], ...] = (
    (r"^(execute|exec|shell|run_code|run_terminal|terminal)$", "block"),
    (r"(delete_|drop_|destroy_)", "block"),
    (r"(write|edit|patch)_file", "warn"),
)

BLOCK_CONFIDENCE = 0.95
WARN_CONFIDENCE = 0.75
ALLOW_CONFIDENCE = 0.5


@dataclass(frozen=True)
class Rule:
    """A deterministic signature rule with severity and remediation guidance."""

    rule_id: str
    name: str
    severity: RuleSeverity
    remediation: str
    matcher: Callable[[Action], bool]


def _shell_text(action: Action) -> str:
    if action.command:
        return action.command.strip()
    if action.args:
        return " ".join(action.args).strip()
    return ""


def _git_text(action: Action) -> str:
    if action.command:
        return action.command.strip()
    if action.args:
        return " ".join(["git", *action.args]).strip()
    return ""


def _file_path(action: Action) -> str:
    if action.path:
        return os.path.expanduser(action.path).replace("\\", "/")
    return ""


def _file_op(action: Action) -> str:
    parts = [part.lower() for part in action.args]
    return parts[0] if parts else ""


def _network_host(action: Action) -> str:
    if not action.url:
        return ""
    parsed = urlparse(action.url)
    return (parsed.hostname or "").lower()


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in markers)


def _path_contains(path: str, markers: tuple[str, ...]) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(marker.lower() in normalized for marker in markers)


def _is_exfil_domain(host: str) -> bool:
    if not host:
        return False
    if host.endswith(".bin"):
        return True
    return any(host == domain or host.endswith(f".{domain}") for domain in EXFIL_DOMAIN_PATTERNS)


def _matches_rm_rf(text: str) -> bool:
    return bool(
        re.search(r"\brm\s+(-[^\s]*f[^\s]*\s+-[^\s]*r|-[^\s]*r[^\s]*\s+-[^\s]*f|-rf|-fr)\s+", text)
    )


def _matches_curl_pipe_shell(text: str) -> bool:
    if not re.search(r"\b(curl|wget)\b", text, re.IGNORECASE):
        return False
    return bool(re.search(r"\|\s*(ba)?sh\b", text))


def _matches_chmod_security(path: str, text: str) -> bool:
    if not re.search(r"\bchmod\b", text):
        return False
    mode_is_dangerous = bool(
        re.search(r"\b(777|\+s|4755|2755)\b", text) or re.search(r"\bchmod\s+[ugoa]*\+[wsx]", text)
    )
    if not mode_is_dangerous:
        return False
    target = path or text
    return _path_contains(target, CREDENTIAL_PATH_MARKERS) or "/.ssh/" in target.lower()


def _matches_git_destructive(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    patterns = (
        r"git\s+push\b[^|]*--force",
        r"git\s+push\b[^|]*-f\b",
        r"git\s+reset\b[^|]*--hard",
        r"git\s+clean\b[^|]*-f",
    )
    return any(re.search(pattern, normalized) for pattern in patterns)


def _matches_credential_dir_write(action: Action) -> bool:
    if action.type != "file":
        return False
    op = _file_op(action)
    if op not in {"write", "create", "append", "patch", "delete", "move", "rename"}:
        return False
    path = _file_path(action)
    return _path_contains(path, CREDENTIAL_DIR_MARKERS)


def _matches_sudo_destructive(text: str) -> bool:
    if not re.search(r"\bsudo\b", text):
        return False
    destructive_patterns = (
        r"\brm\s+(-[^\s]*f[^\s]*\s+-[^\s]*r|-[^\s]*r[^\s]*\s+-[^\s]*f|-rf|-fr)\s+/",
        r"\bmkfs\b",
        r"\bdd\b[^|]*\bof=/dev/",
        r"\bshred\b",
        r"\bformat\b",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in destructive_patterns)


def _matches_download_execute(text: str) -> bool:
    if not re.search(r"\b(curl|wget)\b", text, re.IGNORECASE):
        return False
    if _matches_curl_pipe_shell(text):
        return True
    return bool(
        re.search(r"\b(curl|wget)\b[^|]*\|\s*(python|node|ruby|perl|php)\b", text, re.IGNORECASE)
        or re.search(r"\b(curl|wget)\b[^;]*;\s*(ba)?sh\b", text, re.IGNORECASE)
    )


def _matches_credential_exfil(action: Action) -> bool:
    if action.type == "network":
        host = _network_host(action)
        if not _is_exfil_domain(host) and not _contains_any(host, WEBHOOK_HOST_MARKERS):
            return False
        url_blob = (action.url or "").lower()
        body_blob = str(action.tool_args or "").lower()
        blob = f"{url_blob} {body_blob}"
        return _contains_any(blob, CREDENTIAL_PATH_MARKERS) or any(
            token in blob for token in ("password", "secret", "token", "api_key", "apikey")
        )

    if action.type == "shell":
        text = _shell_text(action).lower()
        if not re.search(r"\b(curl|wget|nc|netcat)\b", text):
            return False
        if not (
            _is_exfil_domain(_extract_url_host(text)) or _contains_any(text, WEBHOOK_HOST_MARKERS)
        ):
            return False
        return _contains_any(text, CREDENTIAL_PATH_MARKERS) or any(
            token in text for token in ("password", "secret", "token", "api_key", "apikey", ".env")
        )

    return False


def _extract_url_host(text: str) -> str:
    match = re.search(r"https?://([^/\s'\"|]+)", text, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _matches_kill_processes(text: str) -> bool:
    if re.search(r"\bkill\s+-9\b", text):
        return True
    if re.search(r"\bpkill\b", text):
        return True
    if re.search(r"\bkillall\b", text):
        return True
    return bool(re.search(r"\bkill\b\s+-9\b", text))


def _matches_db_destructive(action: Action) -> bool:
    if action.type == "shell":
        text = _shell_text(action).lower()
        if re.search(r"\bdrop\s+(table|database)\b", text):
            return True
        if re.search(r"\btruncate\s+table\b", text):
            return True
        return bool(
            re.search(r"\brm\b[^|]*(\.sqlite|\.db|/var/lib/postgresql|/var/lib/mysql)", text)
        )

    if action.type == "file":
        path = _file_path(action).lower()
        op = _file_op(action)
        if op not in {"delete", "write", "append"}:
            return False
        return path.endswith((".sqlite", ".sqlite3", ".db")) or "/var/lib/postgresql" in path

    return False


def _matches_read_sensitive(action: Action) -> bool:
    if action.type != "file":
        return False
    op = _file_op(action)
    if op and op not in {"read", "open", "cat"}:
        return False
    path = _file_path(action)
    return _path_contains(path, CREDENTIAL_PATH_MARKERS)


def _matches_mcp_dangerous(action: Action) -> tuple[bool, RuleSeverity]:
    if action.type != "mcp" or not action.tool:
        return False, "warn"
    tool = action.tool.lower()
    for pattern, severity in MCP_DANGEROUS_TOOL_PATTERNS:
        if re.search(pattern, tool):
            return True, severity
    return False, "warn"


def _matches_chmod_system(action: Action) -> bool:
    text = _shell_text(action) if action.type == "shell" else ""
    path = _file_path(action)
    blob = f"{text} {path}".lower()
    if not re.search(r"\b(chmod|chown)\b", blob):
        return False
    return _path_contains(path or text, SYSTEM_DIR_MARKERS)


def _matches_code_exec(text: str) -> bool:
    patterns = (
        r"\bpython\d*\s+-c\b",
        r"\bpython\d*\s+--command\b",
        r"\bnode\s+-e\b",
        r"\bnode\s+--eval\b",
        r"\bruby\s+-e\b",
        r"\bperl\s+-e\b",
        r"\bphp\s+-r\b",
        r"\b--eval\b",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _matches_devnull_redirect(text: str) -> bool:
    if "/dev/null" not in text:
        return False
    mutating = (
        r"\brm\b",
        r"\bmv\b",
        r"\bcp\b",
        r"\bchmod\b",
        r"\bchown\b",
        r"\bdd\b",
        r"\bgit\s+(push|reset|clean)\b",
        r"\bdrop\s+(table|database)\b",
    )
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in mutating)


def _matches_webhook_post(action: Action) -> bool:
    if action.type != "network":
        return False
    method = (action.method or "GET").upper()
    if method not in {"POST", "PUT", "PATCH"}:
        return False
    host = _network_host(action)
    if not host:
        return False
    if _is_exfil_domain(host):
        return True
    return _contains_any(host, WEBHOOK_HOST_MARKERS)


def _matches_pip_untrusted(text: str) -> bool:
    if not re.search(r"\bpip3?\s+install\b", text, re.IGNORECASE):
        return False
    untrusted_markers = (
        "git+https",
        "git+ssh",
        "git@",
        "--index-url",
        "-i http",
        "--extra-index-url",
        "@master",
        "@main",
    )
    lowered = text.lower()
    return any(marker in lowered for marker in untrusted_markers)


def _match_shell_rm_rf(action: Action) -> bool:
    return action.type == "shell" and _matches_rm_rf(_shell_text(action))


def _match_network_exfil_domains(action: Action) -> bool:
    if action.type != "network":
        return False
    host = _network_host(action)
    return _is_exfil_domain(host)


def _match_shell_curl_pipe_sh(action: Action) -> bool:
    return action.type == "shell" and _matches_curl_pipe_shell(_shell_text(action))


def _match_shell_chmod_security(action: Action) -> bool:
    if action.type == "shell":
        return _matches_chmod_security("", _shell_text(action))
    if action.type == "file":
        return _matches_chmod_security(_file_path(action), " ".join(action.args))
    return False


def _match_git_destructive(action: Action) -> bool:
    if action.type == "git":
        return _matches_git_destructive(_git_text(action))
    if action.type == "shell":
        return _matches_git_destructive(_shell_text(action))
    return False


def _match_file_credential_dirs(action: Action) -> bool:
    return _matches_credential_dir_write(action)


def _match_shell_sudo_destructive(action: Action) -> bool:
    return action.type == "shell" and _matches_sudo_destructive(_shell_text(action))


def _match_shell_download_execute(action: Action) -> bool:
    return action.type == "shell" and _matches_download_execute(_shell_text(action))


def _match_network_credential_exfil(action: Action) -> bool:
    return _matches_credential_exfil(action)


def _match_shell_kill_processes(action: Action) -> bool:
    return action.type == "shell" and _matches_kill_processes(_shell_text(action))


def _match_db_destructive(action: Action) -> bool:
    return _matches_db_destructive(action)


def _match_file_read_sensitive(action: Action) -> bool:
    return _matches_read_sensitive(action)


def _match_mcp_dangerous_block(action: Action) -> bool:
    matched, severity = _matches_mcp_dangerous(action)
    return matched and severity == "block"


def _match_mcp_dangerous_warn(action: Action) -> bool:
    matched, severity = _matches_mcp_dangerous(action)
    return matched and severity == "warn"


def _match_file_chmod_system(action: Action) -> bool:
    return action.type in {"file", "shell"} and _matches_chmod_system(action)


def _match_shell_code_exec(action: Action) -> bool:
    return action.type == "shell" and _matches_code_exec(_shell_text(action))


def _match_shell_devnull_redirect(action: Action) -> bool:
    return action.type == "shell" and _matches_devnull_redirect(_shell_text(action))


def _match_network_webhook_post(action: Action) -> bool:
    return _matches_webhook_post(action)


def _match_shell_pip_untrusted(action: Action) -> bool:
    return action.type == "shell" and _matches_pip_untrusted(_shell_text(action))


RULES: list[Rule] = [
    Rule(
        rule_id="shell-rm-rf",
        name="Recursive force delete",
        severity="block",
        remediation="Avoid `rm -rf`; use safer deletion tools or scoped paths with confirmation.",
        matcher=_match_shell_rm_rf,
    ),
    Rule(
        rule_id="network-exfil-domains",
        name="Credential exfiltration domain",
        severity="block",
        remediation="Do not send data to paste bins, webhooks, or ephemeral upload hosts.",
        matcher=_match_network_exfil_domains,
    ),
    Rule(
        rule_id="shell-curl-pipe-sh",
        name="Remote script pipe to shell",
        severity="block",
        remediation="Download scripts, inspect them, then run explicitly instead of piping to sh/bash.",  # noqa: E501
        matcher=_match_shell_curl_pipe_sh,
    ),
    Rule(
        rule_id="shell-chmod-security",
        name="Dangerous chmod on security files",
        severity="block",
        remediation="Do not loosen permissions on SSH keys, shadow files, or credential stores.",
        matcher=_match_shell_chmod_security,
    ),
    Rule(
        rule_id="git-destructive",
        name="Destructive git operation",
        severity="block",
        remediation="Avoid force push, hard reset, and forced clean; use safer git recovery workflows.",  # noqa: E501
        matcher=_match_git_destructive,
    ),
    Rule(
        rule_id="file-credential-dirs",
        name="Write to credential directories",
        severity="block",
        remediation="Do not write or modify files under ~/.ssh, ~/.aws, or other credential directories.",  # noqa: E501
        matcher=_match_file_credential_dirs,
    ),
    Rule(
        rule_id="shell-sudo-destructive",
        name="Sudo destructive system command",
        severity="block",
        remediation="Avoid privileged destructive commands; require explicit human approval and backups.",  # noqa: E501
        matcher=_match_shell_sudo_destructive,
    ),
    Rule(
        rule_id="shell-download-execute",
        name="Download and execute remote payload",
        severity="block",
        remediation="Fetch artifacts to disk, verify checksums, and execute only after review.",
        matcher=_match_shell_download_execute,
    ),
    Rule(
        rule_id="network-credential-exfil",
        name="Credential content exfiltration",
        severity="block",
        remediation="Never upload secrets, `.env` files, or credential material to external hosts.",
        matcher=_match_network_credential_exfil,
    ),
    Rule(
        rule_id="shell-kill-processes",
        name="Broad or forced process kill",
        severity="warn",
        remediation="Target specific PIDs instead of `kill -9`, `pkill`, or `killall`.",
        matcher=_match_shell_kill_processes,
    ),
    Rule(
        rule_id="db-destructive",
        name="Database destructive operation",
        severity="block",
        remediation="Use migrations/backups instead of DROP/TRUNCATE or deleting database files.",
        matcher=_match_db_destructive,
    ),
    Rule(
        rule_id="file-read-sensitive",
        name="Read sensitive credential file",
        severity="warn",
        remediation="Avoid reading secret files unless strictly required and approved.",
        matcher=_match_file_read_sensitive,
    ),
    Rule(
        rule_id="mcp-dangerous-exec",
        name="Dangerous MCP execution tool",
        severity="block",
        remediation="Use read-only MCP tools or route execution through an approved sandbox.",
        matcher=_match_mcp_dangerous_block,
    ),
    Rule(
        rule_id="mcp-dangerous-write",
        name="Potentially dangerous MCP write tool",
        severity="warn",
        remediation="Confirm MCP file write/edit tools target safe paths before execution.",
        matcher=_match_mcp_dangerous_warn,
    ),
    Rule(
        rule_id="file-chmod-system",
        name="Permission change on system paths",
        severity="warn",
        remediation="Avoid chmod/chown on system directories; use package managers or admin playbooks.",  # noqa: E501
        matcher=_match_file_chmod_system,
    ),
    Rule(
        rule_id="shell-code-exec",
        name="Inline interpreter execution",
        severity="warn",
        remediation="Prefer scripts in version control over inline `-c`, `-e`, or `--eval` execution.",  # noqa: E501
        matcher=_match_shell_code_exec,
    ),
    Rule(
        rule_id="shell-devnull-redirect",
        name="Mutating command hides errors via /dev/null",
        severity="warn",
        remediation="Do not redirect destructive command errors to /dev/null; inspect failures explicitly.",  # noqa: E501
        matcher=_match_shell_devnull_redirect,
    ),
    Rule(
        rule_id="network-webhook-post",
        name="POST to webhook or callback host",
        severity="warn",
        remediation="Confirm webhook destinations and payload contents before sending agent data.",
        matcher=_match_network_webhook_post,
    ),
    Rule(
        rule_id="shell-pip-untrusted",
        name="pip install from untrusted source",
        severity="warn",
        remediation="Install packages from pinned PyPI versions instead of git URLs or custom indexes.",  # noqa: E501
        matcher=_match_shell_pip_untrusted,
    ),
]


def _confidence_for_verdict(verdict: Verdict) -> float:
    if verdict == "block":
        return BLOCK_CONFIDENCE
    if verdict == "warn":
        return WARN_CONFIDENCE
    return ALLOW_CONFIDENCE


def _decision_from_rule(action: Action, rule: Rule) -> Decision:
    return Decision(
        verdict=rule.severity,
        reason=f"{rule.name}: {rule.remediation}",
        confidence=_confidence_for_verdict(rule.severity),
        action_hash=action.to_hash(),
        rule_id=rule.rule_id,
    )


def evaluate(action: Action) -> list[Decision]:
    """Return all rule matches for an action."""
    return [_decision_from_rule(action, rule) for rule in RULES if rule.matcher(action)]


def load_allowlist(path: str | Path) -> set[str]:
    """Load allowlisted rule IDs and command strings from YAML."""
    allowlist_path = Path(path)
    data = yaml.safe_load(allowlist_path.read_text(encoding="utf-8"))
    if data is None:
        return set()
    if not isinstance(data, dict):
        msg = "Allowlist YAML must be a mapping with optional 'rules' and 'commands' keys."
        raise ValueError(msg)

    entries: set[str] = set()
    rules = data.get("rules", [])
    commands = data.get("commands", [])

    if rules is not None:
        if not isinstance(rules, list):
            raise ValueError("Allowlist 'rules' must be a list of rule IDs.")
        entries.update(str(rule_id) for rule_id in rules)

    if commands is not None:
        if not isinstance(commands, list):
            raise ValueError("Allowlist 'commands' must be a list of command strings.")
        entries.update(str(command) for command in commands)

    return entries


def _is_command_allowlisted(action: Action, allowlist: set[str]) -> bool:
    command = _shell_text(action) or _git_text(action)
    if not command:
        return False
    if command in allowlist:
        return True
    command_prefixes = ("git ", "sudo ", "rm ", "curl ")
    return any(entry in command for entry in allowlist if entry.startswith(command_prefixes))


def _downgrade_verdict(verdict: Verdict) -> Verdict:
    if verdict == "block":
        return "warn"
    if verdict == "warn":
        return "allow"
    return "allow"


def _apply_allowlist(
    decisions: list[Decision],
    action: Action,
    allowlist: set[str],
) -> list[Decision]:
    if not decisions:
        return decisions

    command_allowed = _is_command_allowlisted(action, allowlist)
    adjusted: list[Decision] = []

    for decision in decisions:
        rule_allowed = decision.rule_id is not None and decision.rule_id in allowlist
        if not rule_allowed and not command_allowed:
            adjusted.append(decision)
            continue

        downgraded = _downgrade_verdict(decision.verdict)
        if downgraded == "allow":
            continue

        adjusted.append(
            Decision(
                verdict=downgraded,
                reason=f"{decision.reason} (allowlisted; downgraded from {decision.verdict})",
                confidence=_confidence_for_verdict(downgraded),
                action_hash=decision.action_hash,
                rule_id=decision.rule_id,
            )
        )

    return adjusted


def summarize(decisions: list[Decision], action: Action) -> Decision:
    """Collapse rule decisions to a single verdict, highest severity wins."""
    action_hash = action.to_hash()
    if not decisions:
        return Decision(
            verdict="allow",
            reason="no rules matched",
            confidence=ALLOW_CONFIDENCE,
            action_hash=action_hash,
            rule_id=None,
        )

    severity_rank = {"block": 2, "warn": 1, "allow": 0}
    best = max(decisions, key=lambda decision: severity_rank[decision.verdict])

    same_severity = [decision for decision in decisions if decision.verdict == best.verdict]
    if len(same_severity) == 1:
        return same_severity[0]

    matched_ids = {decision.rule_id for decision in same_severity if decision.rule_id}
    rule_ids = ", ".join(sorted(matched_ids))
    reasons = "; ".join(decision.reason for decision in same_severity)
    return Decision(
        verdict=best.verdict,
        reason=reasons,
        confidence=_confidence_for_verdict(best.verdict),
        action_hash=action_hash,
        rule_id=rule_ids or best.rule_id,
    )


def evaluate_with_allowlist(action: Action, allowlist_file: str | Path | None) -> Decision:
    """Evaluate an action and return the final decision, honoring optional allowlist downgrades."""
    decisions = evaluate(action)
    if allowlist_file is None:
        return summarize(decisions, action)

    allowlist = load_allowlist(allowlist_file)
    adjusted = _apply_allowlist(decisions, action, allowlist)
    return summarize(adjusted, action)
