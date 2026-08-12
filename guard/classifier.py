"""Optional heuristic classifier and rule-classifier merge for final confidence.

The classifier is fully offline and deterministic — no ML model or network calls.
It extracts lightweight feature markers from an ``Action`` and returns a
dangerousness score in ``[0.0, 1.0]``.

Merge policy (``RuleClassifierMerger``)
---------------------------------------
1. **Hard block override** — If any matched rule has verdict ``block``, the final
   verdict is always ``block``. The classifier cannot downgrade a block rule.
   Confidence is ``max(0.95, classifier_score)`` clamped to
   ``[0.85, 0.99]``.

2. **Warn path** — If the highest rule severity is ``warn`` (no blocks), the final
   verdict is ``warn``. Confidence is the classifier score mapped to
   ``[WARN_CONFIDENCE_FLOOR, WARN_CONFIDENCE_CEIL]`` (default ``0.55``–``0.90``).

3. **Allow path** — When no rules match, verdict is ``allow``. Confidence is
   ``1.0 - classifier_score`` mapped to ``[ALLOW_CONFIDENCE_FLOOR, ALLOW_CONFIDENCE_CEIL]``
   (default ``0.40``–``0.95``): low dangerousness yields high allow confidence.

4. **No classifier** — When disabled (``--no-classifier`` or ``use_classifier=False``),
   fixed rule confidences apply: block ``0.95``, warn ``0.75``, allow ``0.50``.

Rule verdict selection still follows ``rules.summarize`` (block > warn > allow).
The merger only adjusts confidence except for the hard block override above.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from guard.decision import Decision
from guard.schema import Action

# Fixed confidences used when classifier is disabled (matches rules.py defaults).
RULE_BLOCK_CONFIDENCE = 0.95
RULE_WARN_CONFIDENCE = 0.75
RULE_ALLOW_CONFIDENCE = 0.50

# Classifier-driven confidence bounds.
BLOCK_CONFIDENCE_FLOOR = 0.85
BLOCK_CONFIDENCE_CEIL = 0.99
WARN_CONFIDENCE_FLOOR = 0.55
WARN_CONFIDENCE_CEIL = 0.90
ALLOW_CONFIDENCE_FLOOR = 0.40
ALLOW_CONFIDENCE_CEIL = 0.95

_EXFIL_HOST_MARKERS: tuple[str, ...] = (
    "pastebin.com",
    "pastie.org",
    "transfer.sh",
    "webhook.site",
    "0x0.st",
    "dpaste.org",
    "hastebin.com",
    "hooks.slack.com",
    "discord.com/api/webhooks",
    "ngrok.io",
    "requestbin.com",
    "pipedream.net",
)

_CREDENTIAL_PATH_MARKERS: tuple[str, ...] = (
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

_CREDENTIAL_DIR_MARKERS: tuple[str, ...] = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
)

_MCP_DANGEROUS_TOOL_RE = re.compile(
    r"(^execute$|^exec$|^shell$|^run_code$|^run_terminal$|delete_|drop_|destroy_)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FeatureWeight:
    """Named feature with weight contribution toward dangerousness score."""

    name: str
    weight: float


# Per-feature weights (overlapping features may sum above 1.0; score is clamped).
FEATURE_WEIGHTS: tuple[FeatureWeight, ...] = (
    FeatureWeight("rm_rf", 0.18),
    FeatureWeight("curl_pipe_sh", 0.16),
    FeatureWeight("download_execute", 0.12),
    FeatureWeight("sudo_destructive", 0.14),
    FeatureWeight("network_exfil", 0.10),
    FeatureWeight("credential_path", 0.10),
    FeatureWeight("credential_dir", 0.08),
    FeatureWeight("destructive_git", 0.08),
    FeatureWeight("mcp_dangerous_tool", 0.08),
    FeatureWeight("db_destructive", 0.08),
    FeatureWeight("kill_processes", 0.04),
    FeatureWeight("code_exec", 0.04),
    FeatureWeight("chmod_dangerous", 0.06),
    FeatureWeight("pip_untrusted", 0.04),
    FeatureWeight("webhook_post", 0.04),
)


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


def _action_blob(action: Action) -> str:
    """Concatenate all action fields into a single lowercase search blob."""
    parts: list[str] = []
    if action.command:
        parts.append(action.command)
    if action.args:
        parts.extend(action.args)
    if action.path:
        parts.append(action.path)
    if action.url:
        parts.append(action.url)
    if action.method:
        parts.append(action.method)
    if action.tool:
        parts.append(action.tool)
    if action.tool_args:
        parts.append(str(action.tool_args))
    return " ".join(parts).lower()


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in markers)


def _path_contains(path: str, markers: tuple[str, ...]) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(marker.lower() in normalized for marker in markers)


def _network_host(action: Action) -> str:
    if not action.url:
        return ""
    parsed = urlparse(action.url)
    return (parsed.hostname or "").lower()


def _is_exfil_host(host: str) -> bool:
    if not host:
        return False
    if host.endswith(".bin"):
        return True
    return any(host == domain or host.endswith(f".{domain}") for domain in _EXFIL_HOST_MARKERS)


def extract_features(action: Action) -> dict[str, bool]:
    """Return boolean feature flags used by the heuristic scorer."""
    shell = _shell_text(action)
    git = _git_text(action)
    blob = _action_blob(action)
    path = _file_path(action)
    host = _network_host(action)

    rm_rf = bool(
        re.search(
            r"\brm\s+(-[^\s]*f[^\s]*\s+-[^\s]*r|-[^\s]*r[^\s]*\s+-[^\s]*f|-rf|-fr)\s+",
            shell,
        )
    )

    curl_pipe_sh = bool(
        re.search(r"\b(curl|wget)\b", shell, re.IGNORECASE) and re.search(r"\|\s*(ba)?sh\b", shell)
    )

    download_execute = bool(
        re.search(r"\b(curl|wget)\b", shell, re.IGNORECASE)
        and (
            curl_pipe_sh
            or re.search(r"\|\s*(python|node|ruby|perl|php)\b", shell, re.IGNORECASE)
            or re.search(r";\s*(ba)?sh\b", shell, re.IGNORECASE)
        )
    )

    sudo_destructive = bool(
        re.search(r"\bsudo\b", shell)
        and re.search(
            r"\b(rm\s+(-[^\s]*f|-rf|-fr)\s+/|mkfs\b|dd\b[^|]*\bof=/dev/|shred\b)",
            shell,
            re.IGNORECASE,
        )
    )

    network_exfil = _is_exfil_host(host) or bool(
        action.type == "shell"
        and re.search(r"\b(curl|wget|nc|netcat)\b", shell, re.IGNORECASE)
        and bool(re.search(r"https?://", shell, re.IGNORECASE))
        and _contains_any(shell, _EXFIL_HOST_MARKERS)
    )

    credential_path = _path_contains(path or blob, _CREDENTIAL_PATH_MARKERS) or _contains_any(
        blob, _CREDENTIAL_PATH_MARKERS
    )

    credential_dir = _path_contains(path, _CREDENTIAL_DIR_MARKERS)

    destructive_git = bool(
        re.search(
            r"git\s+(push\b[^|]*(--force|-f\b)|reset\b[^|]*--hard|clean\b[^|]*-f)",
            f"{git} {shell}".lower(),
        )
    )

    mcp_dangerous_tool = action.type == "mcp" and bool(
        action.tool and _MCP_DANGEROUS_TOOL_RE.search(action.tool)
    )

    db_destructive = bool(
        re.search(r"\b(drop\s+(table|database)|truncate\s+table)\b", blob)
        or bool(re.search(r"\brm\b[^|]*(\\.sqlite|\\.db|/var/lib/postgresql|/var/lib/mysql)", blob))
    )

    kill_processes = bool(re.search(r"\b(kill\s+-9|pkill\b|killall\b)\b", shell, re.IGNORECASE))

    code_exec = bool(
        re.search(
            r"\b(python\d*\s+(-c|--command)|node\s+(-e|--eval)|ruby\s+-e|perl\s+-e|php\s+-r|--eval)\b",
            shell,
            re.IGNORECASE,
        )
    )

    chmod_dangerous = bool(
        re.search(r"\bchmod\b", blob)
        and re.search(r"\b(777|\+s|4755|2755)\b", blob)
        and (_path_contains(path or shell, _CREDENTIAL_PATH_MARKERS) or ".ssh" in blob)
    )

    pip_untrusted = bool(
        re.search(r"\bpip3?\s+install\b", shell, re.IGNORECASE)
        and _contains_any(
            shell,
            ("git+https", "git+ssh", "git@", "--index-url", "--extra-index-url"),
        )
    )

    webhook_post = (
        action.type == "network"
        and (action.method or "GET").upper()
        in {
            "POST",
            "PUT",
            "PATCH",
        }
        and (
            _is_exfil_host(host)
            or any(marker in host for marker in ("webhook", "callback", "hook", "requestbin"))
        )
    )

    return {
        "rm_rf": rm_rf,
        "curl_pipe_sh": curl_pipe_sh,
        "download_execute": download_execute,
        "sudo_destructive": sudo_destructive,
        "network_exfil": network_exfil,
        "credential_path": credential_path,
        "credential_dir": credential_dir,
        "destructive_git": destructive_git,
        "mcp_dangerous_tool": mcp_dangerous_tool,
        "db_destructive": db_destructive,
        "kill_processes": kill_processes,
        "code_exec": code_exec,
        "chmod_dangerous": chmod_dangerous,
        "pip_untrusted": pip_untrusted,
        "webhook_post": webhook_post,
    }


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _lerp(score: float, low: float, high: float) -> float:
    return low + score * (high - low)


class Classifier:
    """Lightweight deterministic dangerousness scorer (offline, no model)."""

    def score(self, action: Action) -> float:
        """Return dangerousness in ``[0.0, 1.0]`` from weighted feature heuristics."""
        features = extract_features(action)
        total = sum(fw.weight for fw in FEATURE_WEIGHTS if features.get(fw.name, False))
        return _clamp(round(total, 4), 0.0, 1.0)

    def features(self, action: Action) -> dict[str, bool]:
        """Expose matched features (for tests and debugging)."""
        return extract_features(action)


class RuleClassifierMerger:
    """Merge rule decisions with a classifier score into a final ``Decision``."""

    def merge(
        self,
        rule_decisions: list[Decision],
        action: Action,
        classifier_score: float,
    ) -> Decision:
        """Apply merge policy; see module docstring for precedence rules."""
        from guard.rules import summarize

        base = summarize(rule_decisions, action)
        score = _clamp(classifier_score, 0.0, 1.0)

        if base.verdict == "block":
            confidence = _clamp(
                max(RULE_BLOCK_CONFIDENCE, score),
                BLOCK_CONFIDENCE_FLOOR,
                BLOCK_CONFIDENCE_CEIL,
            )
            return Decision(
                verdict="block",
                reason=base.reason,
                confidence=round(confidence, 2),
                action_hash=base.action_hash,
                rule_id=base.rule_id,
            )

        if base.verdict == "warn":
            confidence = _lerp(score, WARN_CONFIDENCE_FLOOR, WARN_CONFIDENCE_CEIL)
            return Decision(
                verdict="warn",
                reason=base.reason,
                confidence=round(confidence, 2),
                action_hash=base.action_hash,
                rule_id=base.rule_id,
            )

        # allow — no rules matched
        safety = 1.0 - score
        confidence = _lerp(safety, ALLOW_CONFIDENCE_FLOOR, ALLOW_CONFIDENCE_CEIL)
        return Decision(
            verdict="allow",
            reason=base.reason,
            confidence=round(confidence, 2),
            action_hash=base.action_hash,
            rule_id=base.rule_id,
        )

    def merge_without_classifier(
        self,
        rule_decisions: list[Decision],
        action: Action,
    ) -> Decision:
        """Deterministic merge using fixed rule confidences only."""
        from guard.rules import summarize

        base = summarize(rule_decisions, action)
        if base.verdict == "block":
            confidence = RULE_BLOCK_CONFIDENCE
        elif base.verdict == "warn":
            confidence = RULE_WARN_CONFIDENCE
        else:
            confidence = RULE_ALLOW_CONFIDENCE

        return Decision(
            verdict=base.verdict,
            reason=base.reason,
            confidence=confidence,
            action_hash=base.action_hash,
            rule_id=base.rule_id,
        )


def merge_decisions(
    rule_decisions: list[Decision],
    action: Action,
    *,
    classifier_score: float | None = None,
) -> Decision:
    """Convenience wrapper: classifier on when ``classifier_score`` is provided."""
    merger = RuleClassifierMerger()
    if classifier_score is None:
        return merger.merge_without_classifier(rule_decisions, action)
    return merger.merge(rule_decisions, action, classifier_score)
