#!/usr/bin/env python3
"""
Skill Bouncer — Pre-installation security gate for ZeroClaw skills.

Inspired by IronClaw's defense-in-depth safety patterns, Skill Bouncer
performs multi-layer security analysis on skill directories before they
are installed into ZeroClaw. Think of it as the bouncer at the club:
no weapons, no contraband, no trouble.

Layers:
  1. Structure check   — manifest present, no symlinks, no banned file types
  2. Credential scan   — secrets, tokens, API keys, private keys in content
  3. Leak detection    — URLs, IPs, emails, hardcoded endpoints that leak data
  4. Command analysis  — shell injection, chaining, high-risk destructive ops
  5. Permission audit  — tool kinds, network access, filesystem scope
  6. Policy engine     — severity × action rules produce final verdict

Usage:
  python3 scripts/skill-bouncer.py <skill-directory>
  python3 scripts/skill-bouncer.py <skill-directory> --json
  python3 scripts/skill-bouncer.py <skill-directory> --strict

Exit codes:
  0 — PASS  (no findings, or warnings only in non-strict mode)
  1 — BLOCK (critical/high findings that prevent installation)
  2 — REVIEW (medium findings that need human review)
  3 — ERROR (script error, invalid arguments)
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import Optional


# ─── Severity & Action Enums ───────────────────────────────────────────────

class Severity(IntEnum):
    """Finding severity levels, inspired by IronClaw's policy engine."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name


class Action(IntEnum):
    """Policy actions mapped from severity."""
    PASS = 0
    WARN = 1
    REVIEW = 2
    BLOCK = 3

    def label(self) -> str:
        return self.name


# ─── Finding Data Model ───────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding from any scan layer."""
    layer: str
    severity: Severity
    action: Action
    file: str
    message: str
    pattern: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "layer": self.layer,
            "severity": self.severity.label(),
            "action": self.action.label(),
            "file": self.file,
            "message": self.message,
            "pattern": self.pattern,
            "line": self.line,
        }


@dataclass
class BouncerReport:
    """Aggregated report from all scan layers."""
    skill_dir: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    verdict: str = "PASS"
    verdict_action: int = 0

    def add(self, finding: Finding):
        self.findings.append(finding)

    def compute_verdict(self, strict: bool = False):
        """Compute final verdict based on worst finding action."""
        if not self.findings:
            self.verdict = "PASS"
            self.verdict_action = 0
            return

        worst = max(f.action for f in self.findings)
        if worst >= Action.BLOCK:
            self.verdict = "BLOCK"
            self.verdict_action = 1
        elif worst >= Action.REVIEW:
            self.verdict = "REVIEW"
            self.verdict_action = 2
        elif strict and worst >= Action.WARN:
            self.verdict = "REVIEW"
            self.verdict_action = 2
        else:
            self.verdict = "PASS"
            self.verdict_action = 0

    def to_dict(self) -> dict:
        return {
            "skill_dir": self.skill_dir,
            "files_scanned": self.files_scanned,
            "verdict": self.verdict,
            "findings_count": len(self.findings),
            "findings_by_severity": {
                s.label(): sum(1 for f in self.findings if f.severity == s)
                for s in Severity
                if any(f.severity == s for f in self.findings)
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── Pattern Databases ────────────────────────────────────────────────────
# Inspired by IronClaw's Aho-Corasick multi-pattern matching approach.
# We use compiled regex for the Python implementation.

# Layer 2: Credential / Secret patterns
CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # API keys and tokens (generic)
    (re.compile(r'(?i)(?:api[_-]?key|api[_-]?secret|api[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}'),
     "api-key-assignment", Severity.CRITICAL),
    # AWS access keys
    (re.compile(r'(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9]|$)'),
     "aws-access-key", Severity.CRITICAL),
    # AWS secret keys (40 char base64)
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}'),
     "aws-secret-key", Severity.CRITICAL),
    # GitHub tokens (classic and fine-grained)
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}'),
     "github-token", Severity.CRITICAL),
    # Generic bearer tokens
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}'),
     "bearer-token", Severity.HIGH),
    # Private keys (PEM)
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
     "private-key-pem", Severity.CRITICAL),
    # SSH private keys
    (re.compile(r'-----BEGIN\s+(?:OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----'),
     "ssh-private-key", Severity.CRITICAL),
    # Generic password assignments
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']'),
     "hardcoded-password", Severity.HIGH),
    # Slack tokens
    (re.compile(r'xox[boaprs]-[0-9A-Za-z\-]{10,}'),
     "slack-token", Severity.CRITICAL),
    # Discord bot tokens
    (re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'),
     "discord-token", Severity.CRITICAL),
    # Generic hex secrets (32+ chars assigned to a "secret" variable)
    (re.compile(r'(?i)(?:secret|token|credential)\s*[:=]\s*["\']?[0-9a-f]{32,}'),
     "hex-secret", Severity.HIGH),
    # .env file references that embed values
    (re.compile(r'(?i)(?:OPENAI|ANTHROPIC|COHERE|MISTRAL|HUGGINGFACE)[_-]?(?:API[_-]?)?KEY\s*=\s*\S{10,}'),
     "env-api-key", Severity.CRITICAL),
]

# Layer 3: Leak detection patterns
LEAK_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # Hardcoded IP addresses (non-localhost, non-example)
    (re.compile(r'(?<!\d)(?!127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)'),
     "hardcoded-ip", Severity.MEDIUM),
    # Webhook URLs
    (re.compile(r'https?://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|hooks\.zapier\.com)/\S+'),
     "webhook-url", Severity.HIGH),
    # Data exfiltration patterns (curl/wget to external with file upload)
    (re.compile(r'(?i)(?:curl|wget)\s+[^\n]*(?:-F\s|--data|--upload-file|-T\s)\s*[^\n]*https?://'),
     "data-exfil-upload", Severity.CRITICAL),
    # Base64-encoded blobs (potential obfuscation)
    (re.compile(r'(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{64,}={0,2})(?:[^A-Za-z0-9+/]|$)'),
     "base64-blob", Severity.LOW),
    # Encoded/obfuscated content (hex-encoded strings)
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}'),
     "hex-encoded-content", Severity.MEDIUM),
    # Email addresses in content (possible data leak)
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
     "email-address", Severity.LOW),
]

# Layer 4: Command analysis patterns
COMMAND_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # curl/wget pipe to shell
    (re.compile(r'(?im)\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh|python|perl|ruby)\b'),
     "pipe-to-shell", Severity.CRITICAL),
    # Destructive filesystem operations
    (re.compile(r'(?im)\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[^\n]*\s+/'),
     "destructive-rm", Severity.CRITICAL),
    # Fork bombs
    (re.compile(r':\(\)\s*\{\s*:\|\s*:&\s*\}\s*;?\s*:'),
     "fork-bomb", Severity.CRITICAL),
    # Disk overwrite
    (re.compile(r'(?im)\bdd\s+if='),
     "disk-overwrite", Severity.CRITICAL),
    # Filesystem format
    (re.compile(r'(?im)\bmkfs(?:\.[a-z0-9]+)?\s'),
     "filesystem-format", Severity.CRITICAL),
    # Netcat reverse shell
    (re.compile(r'(?im)\bnc(?:at)?\b[^\n]{0,120}\s-[elp]'),
     "netcat-shell", Severity.CRITICAL),
    # PowerShell Invoke-Expression
    (re.compile(r'(?im)\b(?:invoke-expression|iex)\b'),
     "powershell-iex", Severity.CRITICAL),
    # Shell chaining in tool commands
    (re.compile(r'(?:&&|\|\||;|`|\$\()'),
     "shell-chaining", Severity.HIGH),
    # Eval/exec in Python/JS
    (re.compile(r'(?im)\b(?:eval|exec)\s*\('),
     "eval-exec", Severity.HIGH),
    # Reverse shell patterns
    (re.compile(r'(?im)/dev/tcp/|bash\s+-i\s+>&|python\s+-c\s+[\'"]import\s+socket'),
     "reverse-shell", Severity.CRITICAL),
    # Cron/systemd persistence
    (re.compile(r'(?im)(?:crontab|systemctl\s+(?:enable|start)|/etc/cron)'),
     "persistence-mechanism", Severity.HIGH),
    # sudo/privilege escalation
    (re.compile(r'(?im)\bsudo\s'),
     "sudo-usage", Severity.MEDIUM),
    # Environment variable manipulation
    (re.compile(r'(?im)\bexport\s+(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)\s*='),
     "env-manipulation", Severity.HIGH),
    # chmod 777 or overly permissive
    (re.compile(r'(?im)\bchmod\s+(?:777|a\+[rwx])'),
     "permissive-chmod", Severity.MEDIUM),
]

# File types that are always blocked
BLOCKED_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".ksh", ".fish",
    ".ps1", ".bat", ".cmd",
    ".exe", ".dll", ".so", ".dylib",
    ".bin", ".com", ".msi",
    ".jar", ".class", ".war",
    ".pyc", ".pyo",
}

# Maximum file size for text scanning (512 KB)
MAX_SCAN_BYTES = 512 * 1024


# ─── Scan Layers ──────────────────────────────────────────────────────────

def layer_structure(skill_dir: Path, report: BouncerReport):
    """Layer 1: Structure check — manifest, symlinks, banned files."""
    has_manifest = (
        (skill_dir / "SKILL.md").is_file()
        or (skill_dir / "SKILL.toml").is_file()
    )
    if not has_manifest:
        report.add(Finding(
            layer="structure",
            severity=Severity.HIGH,
            action=Action.BLOCK,
            file=".",
            message="Missing SKILL.md or SKILL.toml manifest. "
                    "All skills must include a manifest for auditing.",
        ))

    for root, dirs, files in os.walk(skill_dir):
        # Skip .git directories
        dirs[:] = [d for d in dirs if d != ".git"]

        for name in files:
            filepath = Path(root) / name
            rel = filepath.relative_to(skill_dir)
            report.files_scanned += 1

            # Check symlinks
            if filepath.is_symlink():
                report.add(Finding(
                    layer="structure",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    file=str(rel),
                    message="Symlinks are not allowed in skill directories.",
                ))
                continue

            # Check blocked file extensions
            ext = filepath.suffix.lower()
            if ext in BLOCKED_EXTENSIONS:
                report.add(Finding(
                    layer="structure",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    file=str(rel),
                    pattern=f"blocked-extension:{ext}",
                    message=f"File type '{ext}' is blocked by skill security policy.",
                ))
                continue

            # Check for shebang in text files
            if ext not in BLOCKED_EXTENSIONS and filepath.stat().st_size > 0:
                try:
                    with open(filepath, "rb") as f:
                        head = f.read(128)
                    if head.startswith(b"#!"):
                        shebang = head.decode("utf-8", errors="replace").lower()
                        if any(s in shebang for s in ["sh", "bash", "zsh", "python", "perl", "ruby", "node", "pwsh"]):
                            report.add(Finding(
                                layer="structure",
                                severity=Severity.HIGH,
                                action=Action.BLOCK,
                                file=str(rel),
                                pattern="shebang-script",
                                message="File has an executable shebang and is blocked.",
                            ))
                except (OSError, UnicodeDecodeError):
                    pass

            # Check for hidden files (potential malware hiding)
            if name.startswith(".") and name not in {".gitignore", ".gitkeep"}:
                report.add(Finding(
                    layer="structure",
                    severity=Severity.LOW,
                    action=Action.WARN,
                    file=str(rel),
                    pattern="hidden-file",
                    message="Hidden file detected. Review for legitimacy.",
                ))


def layer_credentials(skill_dir: Path, report: BouncerReport):
    """Layer 2: Credential scan — secrets, tokens, keys in file content."""
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = [d for d in dirs if d != ".git"]

        for name in files:
            filepath = Path(root) / name
            rel = filepath.relative_to(skill_dir)

            if not _is_text_scannable(filepath):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for line_num, line in enumerate(content.splitlines(), start=1):
                for pattern, label, severity in CREDENTIAL_PATTERNS:
                    if pattern.search(line):
                        report.add(Finding(
                            layer="credentials",
                            severity=severity,
                            action=_severity_to_action(severity),
                            file=str(rel),
                            pattern=label,
                            message=f"Potential credential detected: {label}",
                            line=line_num,
                        ))
                        break  # One finding per line per layer


def layer_leaks(skill_dir: Path, report: BouncerReport):
    """Layer 3: Leak detection — URLs, IPs, emails, obfuscated content."""
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = [d for d in dirs if d != ".git"]

        for name in files:
            filepath = Path(root) / name
            rel = filepath.relative_to(skill_dir)

            if not _is_text_scannable(filepath):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for line_num, line in enumerate(content.splitlines(), start=1):
                for pattern, label, severity in LEAK_PATTERNS:
                    if pattern.search(line):
                        report.add(Finding(
                            layer="leaks",
                            severity=severity,
                            action=_severity_to_action(severity),
                            file=str(rel),
                            pattern=label,
                            message=f"Potential data leak pattern: {label}",
                            line=line_num,
                        ))
                        break  # One finding per line per layer


def layer_commands(skill_dir: Path, report: BouncerReport):
    """Layer 4: Command analysis — injection, chaining, destructive ops."""
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = [d for d in dirs if d != ".git"]

        for name in files:
            filepath = Path(root) / name
            rel = filepath.relative_to(skill_dir)

            if not _is_text_scannable(filepath):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # For TOML manifests, focus on tool command fields
            if filepath.suffix.lower() == ".toml":
                _scan_toml_commands(filepath, rel, content, report)
            else:
                # For markdown and other text files, scan full content
                for line_num, line in enumerate(content.splitlines(), start=1):
                    for pattern, label, severity in COMMAND_PATTERNS:
                        # Skip shell-chaining check on non-command contexts
                        if label == "shell-chaining":
                            continue
                        if pattern.search(line):
                            report.add(Finding(
                                layer="commands",
                                severity=severity,
                                action=_severity_to_action(severity),
                                file=str(rel),
                                pattern=label,
                                message=f"Dangerous command pattern: {label}",
                                line=line_num,
                            ))
                            break


def _scan_toml_commands(filepath: Path, rel: Path, content: str, report: BouncerReport):
    """Parse TOML manifest and scan tool commands specifically."""
    try:
        # Use simple regex extraction for TOML tool commands
        # This avoids requiring the toml package as a dependency
        tool_blocks = re.finditer(
            r'\[\[tools\]\](.*?)(?=\[\[|\Z)',
            content,
            re.DOTALL,
        )
        for block in tool_blocks:
            block_text = block.group(1)
            cmd_match = re.search(r'command\s*=\s*"([^"]*)"', block_text)
            if not cmd_match:
                cmd_match = re.search(r"command\s*=\s*'([^']*)'", block_text)
            if not cmd_match:
                continue

            command = cmd_match.group(1)
            line_num = content[:block.start()].count("\n") + 1

            for pattern, label, severity in COMMAND_PATTERNS:
                if pattern.search(command):
                    report.add(Finding(
                        layer="commands",
                        severity=severity,
                        action=_severity_to_action(severity),
                        file=str(rel),
                        pattern=label,
                        message=f"Tool command contains dangerous pattern: {label}",
                        line=line_num,
                    ))
    except Exception:
        pass  # If TOML parsing fails, structure layer already catches it


def layer_permissions(skill_dir: Path, report: BouncerReport):
    """Layer 5: Permission audit — tool kinds, network access, scope."""
    toml_path = skill_dir / "SKILL.toml"
    if not toml_path.is_file():
        return

    try:
        content = toml_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    # Extract tool kinds
    tool_blocks = re.finditer(
        r'\[\[tools\]\](.*?)(?=\[\[|\Z)',
        content,
        re.DOTALL,
    )

    shell_count = 0
    http_count = 0

    for block in tool_blocks:
        block_text = block.group(1)
        kind_match = re.search(r'kind\s*=\s*"([^"]*)"', block_text)
        kind = kind_match.group(1).lower() if kind_match else "unknown"

        if kind == "shell":
            shell_count += 1
        elif kind == "http":
            http_count += 1

        # Check for URL references in tool args (network scope)
        if re.search(r'https?://', block_text):
            report.add(Finding(
                layer="permissions",
                severity=Severity.MEDIUM,
                action=Action.REVIEW,
                file="SKILL.toml",
                pattern="network-access",
                message=f"Tool of kind '{kind}' references external URL.",
            ))

    if shell_count > 5:
        report.add(Finding(
            layer="permissions",
            severity=Severity.MEDIUM,
            action=Action.REVIEW,
            file="SKILL.toml",
            pattern="excessive-shell-tools",
            message=f"Skill defines {shell_count} shell tools. "
                    f"Review for necessity and scope.",
        ))

    if http_count > 10:
        report.add(Finding(
            layer="permissions",
            severity=Severity.LOW,
            action=Action.WARN,
            file="SKILL.toml",
            pattern="many-http-tools",
            message=f"Skill defines {http_count} HTTP tools. "
                    f"Review for necessity.",
        ))


# ─── Policy Engine ────────────────────────────────────────────────────────

def _severity_to_action(severity: Severity) -> Action:
    """Map severity to default action, inspired by IronClaw's policy rules."""
    return {
        Severity.LOW: Action.WARN,
        Severity.MEDIUM: Action.REVIEW,
        Severity.HIGH: Action.BLOCK,
        Severity.CRITICAL: Action.BLOCK,
    }[severity]


# ─── Utilities ────────────────────────────────────────────────────────────

def _is_text_scannable(filepath: Path) -> bool:
    """Check if a file should be scanned as text content."""
    if filepath.is_symlink():
        return False
    try:
        size = filepath.stat().st_size
    except OSError:
        return False
    if size == 0 or size > MAX_SCAN_BYTES:
        return False
    # Skip binary extensions
    ext = filepath.suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
               ".mp3", ".mp4", ".wav", ".ogg", ".flac",
               ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
               ".wasm", ".pdf"}:
        return False
    return True


# ─── Output Formatting ────────────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.LOW: "\033[36m",       # cyan
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.HIGH: "\033[31m",      # red
    Severity.CRITICAL: "\033[1;31m",  # bold red
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_report(report: BouncerReport):
    """Print a human-readable report to stderr."""
    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}", file=sys.stderr)
    print(f"{BOLD}║        SKILL BOUNCER — SCAN REPORT       ║{RESET}", file=sys.stderr)
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n", file=sys.stderr)

    print(f"  Skill:  {report.skill_dir}", file=sys.stderr)
    print(f"  Files:  {report.files_scanned} scanned", file=sys.stderr)

    if not report.findings:
        print(f"\n  {BOLD}\033[32m✓ CLEAN — No findings.{RESET}\n", file=sys.stderr)
        return

    # Group by layer
    by_layer: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_layer.setdefault(f.layer, []).append(f)

    total = len(report.findings)
    crit = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in report.findings if f.severity == Severity.HIGH)
    med = sum(1 for f in report.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in report.findings if f.severity == Severity.LOW)

    print(f"  Total:  {total} finding(s)  "
          f"[{SEVERITY_COLORS[Severity.CRITICAL]}C:{crit}{RESET} "
          f"{SEVERITY_COLORS[Severity.HIGH]}H:{high}{RESET} "
          f"{SEVERITY_COLORS[Severity.MEDIUM]}M:{med}{RESET} "
          f"{SEVERITY_COLORS[Severity.LOW]}L:{low}{RESET}]",
          file=sys.stderr)

    for layer_name, findings in sorted(by_layer.items()):
        print(f"\n  {BOLD}── {layer_name.upper()} ──{RESET}", file=sys.stderr)
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            loc = f.file
            if f.line:
                loc += f":{f.line}"
            tag = f"[{f.severity.label()}]"
            print(f"    {color}{tag:10}{RESET} {loc}", file=sys.stderr)
            print(f"             {f.message}", file=sys.stderr)
            if f.pattern:
                print(f"             {DIM}pattern: {f.pattern}{RESET}", file=sys.stderr)

    # Verdict
    if report.verdict == "PASS":
        icon, color = "✓", "\033[32m"
    elif report.verdict == "REVIEW":
        icon, color = "⚠", "\033[33m"
    else:
        icon, color = "✗", "\033[31m"

    print(f"\n  {BOLD}{color}{icon} VERDICT: {report.verdict}{RESET}\n", file=sys.stderr)


# ─── Main ─────────────────────────────────────────────────────────────────

def bounce(skill_dir: Path, strict: bool = False) -> BouncerReport:
    """Run all scan layers and compute verdict."""
    report = BouncerReport(skill_dir=str(skill_dir))

    # Run all layers in sequence (IronClaw double-checkpoint pattern)
    layer_structure(skill_dir, report)
    layer_credentials(skill_dir, report)
    layer_leaks(skill_dir, report)
    layer_commands(skill_dir, report)
    layer_permissions(skill_dir, report)

    report.compute_verdict(strict=strict)
    return report


def main():
    parser = argparse.ArgumentParser(
        prog="skill-bouncer",
        description="Pre-installation security gate for ZeroClaw skills.",
    )
    parser.add_argument(
        "skill_dir",
        type=Path,
        help="Path to the skill directory to scan.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON to stdout.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as review-required (stricter gate).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable output (useful with --json).",
    )

    args = parser.parse_args()

    if not args.skill_dir.is_dir():
        print(f"Error: '{args.skill_dir}' is not a directory.", file=sys.stderr)
        sys.exit(3)

    report = bounce(args.skill_dir, strict=args.strict)

    if not args.quiet:
        print_report(report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))

    sys.exit(report.verdict_action)


if __name__ == "__main__":
    main()
