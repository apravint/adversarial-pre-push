"""
CLI Entrypoint for adversarial-pre-push
"""

import sys
import os
import stat
import json
import argparse
from typing import Optional
from .audit import AdversarialAuditor

HOOK_TEMPLATE = """#!/usr/bin/env bash
# Installed by adversarial-pre-push
set -euo pipefail

echo "🛡️  Running adversarial-pre-push audit..."

if command -v adversarial-pre-push >/dev/null 2>&1; then
    adversarial-pre-push audit . --fail-on HIGH
else
    python3 -m adversarial_pre_push.cli audit . --fail-on HIGH
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ git push blocked by adversarial-pre-push! Resolve high/critical security findings before pushing."
    exit 1
fi

echo "✅ Adversarial audit verified clean. Proceeding with push."
exit 0
"""

def install_git_hook(target_dir: str, force: bool = False) -> bool:
    repo_dir = os.path.abspath(target_dir)
    git_dir = os.path.join(repo_dir, ".git")
    if not os.path.isdir(git_dir):
        print(f"Error: Not a git repository: {repo_dir}", file=sys.stderr)
        return False

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-push")

    if os.path.exists(hook_path) and not force:
        print(f"Hook already exists at {hook_path}. Use --force to overwrite.", file=sys.stderr)
        return False

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(HOOK_TEMPLATE)

    # chmod +x
    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed executable pre-push hook: {hook_path}")
    return True

def main():
    parser = argparse.ArgumentParser(
        prog="adversarial-pre-push",
        description="6-Phase Adversarial Security Audit Git Hook & Engine"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Run adversarial vulnerability scan")
    audit_parser.add_argument("path", nargs="?", default=".", help="Directory or repository to audit")
    audit_parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    audit_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Exit with non-zero status if findings equal or exceed this severity (default: HIGH)"
    )

    # Hook installation subcommand
    hook_parser = subparsers.add_parser("install-hook", help="Install pre-push hook into .git/hooks/pre-push")
    hook_parser.add_argument("path", nargs="?", default=".", help="Target git repository path")
    hook_parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing hook")

    args = parser.parse_args()

    # Default to audit if no command given
    if not args.command or args.command == "audit":
        path = getattr(args, "path", ".")
        as_json = getattr(args, "json", False)
        fail_on = getattr(args, "fail_on", "HIGH")

        auditor = AdversarialAuditor(path)
        findings = auditor.scan()

        if as_json:
            print(json.dumps(findings, indent=2))
        else:
            print(auditor.format_report(findings))

        # Check threshold
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_idx = severity_order.index(fail_on)
        critical_violations = [
            f for f in findings.get("confirmed", [])
            if severity_order.index(f["severity"]) >= min_idx
        ]

        if critical_violations:
            sys.exit(1)
        sys.exit(0)

    elif args.command == "install-hook":
        success = install_git_hook(args.path, force=args.force)
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
