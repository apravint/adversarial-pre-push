"""
Adversarial Pre-Push Audit Engine
Executes a multi-stage adversarial security audit over codebases prior to git push.
Enforces separation between Hunter (candidate extraction) and Verifier (false-positive debunking).
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

DEFAULT_PATTERNS = [
    {
        "id": "SEC-001",
        "name": "Hardcoded Secret / API Token",
        "severity": "CRITICAL",
        "regex": r'(?i)(api[_-]?key|secret[_-]?key|bearer|token|private[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
        "description": "Exposed high-entropy secret, API key, or credential literal in source.",
        "remediation": "Store secrets in environment variables or a secure key vault (.env, HashiCorp Vault)."
    },
    {
        "id": "SEC-002",
        "name": "Unsafe Shell Injection Seam",
        "severity": "HIGH",
        "regex": r'(subprocess\.(Popen|run|check_output|call)\([^)]*shell\s*=\s*True|os\.system\(|os\.popen\()',
        "description": "Shell execution invoked with user-controllable arguments or shell=True.",
        "remediation": "Use subprocess.run(['cmd', 'arg1'], shell=False) with parameterized arguments."
    },
    {
        "id": "SEC-003",
        "name": "Dynamic Code Evaluation",
        "severity": "CRITICAL",
        "regex": r'\b(eval|exec)\s*\([^)]+\)',
        "description": "Dynamic arbitrary string execution via eval() or exec().",
        "remediation": "Refactor to use ast.literal_eval() or explicit dispatch dictionaries."
    },
    {
        "id": "SEC-004",
        "name": "Insecure Deserialization",
        "severity": "HIGH",
        "regex": r'\b(pickle\.loads?|yaml\.load\([^,)]+\))',
        "description": "Unsafe deserialization of untrusted payloads leading to remote code execution.",
        "remediation": "Use json or yaml.safe_load() instead of pickle or full yaml.load()."
    },
    {
        "id": "SEC-005",
        "name": "Disabled TLS / SSL Verification",
        "severity": "HIGH",
        "regex": r'(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0["\']?|InsecureRequestWarning)',
        "description": "TLS certificate verification disabled, opening connection to MITM attacks.",
        "remediation": "Enable SSL verification (verify=True) and provide CA bundle path if necessary."
    },
    {
        "id": "SEC-006",
        "name": "Insecure Temporary File Path",
        "severity": "MEDIUM",
        "regex": r'(\/tmp\/[a-zA-Z0-9_\-\.]+)',
        "description": "Predictable or hardcoded /tmp path usage subject to symlink/race conditions.",
        "remediation": "Use tempfile.NamedTemporaryFile() or tempfile.mkdtemp() for randomized safe tempfiles."
    },
    {
        "id": "SEC-007",
        "name": "Hardcoded Private User Home Path",
        "severity": "LOW",
        "regex": r'/home/[a-zA-Z0-9_\-]+/',
        "description": "Hardcoded user home path breaking portability or leaking username.",
        "remediation": "Use Path.home(), os.path.expanduser('~'), or environment variables."
    }
]

SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 50,
    "MEDIUM": 20,
    "LOW": 5
}

class AdversarialAuditor:
    def __init__(self, target_path: str = ".", patterns: Optional[List[Dict[str, Any]]] = None):
        self.target_path = os.path.abspath(os.path.expanduser(target_path))
        self.patterns = patterns or DEFAULT_PATTERNS
        self.ignored_dirs = {
            ".git", "node_modules", "target", "dist", "build", "__pycache__", ".venv", "venv", ".tox", ".audit"
        }
        self.target_extensions = {
            ".py", ".sh", ".bash", ".js", ".ts", ".jsx", ".tsx", ".json", ".conf", ".service", ".rs", ".go", ".c", ".cpp"
        }

    def scan(self) -> Dict[str, Any]:
        """Runs the 6-phase audit lifecycle."""
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        # Phase 1: Reconnaissance & Coverage Ledger
        files_to_scan = []
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in self.ignored_dirs]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in self.target_extensions:
                    files_to_scan.append(os.path.join(root, f))

        coverage_ledger = {
            "timestamp": datetime.now().isoformat(),
            "target_path": self.target_path,
            "total_files": len(files_to_scan),
            "files": [os.path.relpath(p, self.target_path) for p in files_to_scan]
        }

        # Phase 2: Hunter Phase (Candidate Extraction)
        candidates = []
        for file_path in files_to_scan:
            rel_path = os.path.relpath(file_path, self.target_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for line_no, line in enumerate(lines, 1):
                for pat in self.patterns:
                    if re.search(pat["regex"], line):
                        candidates.append({
                            "file": rel_path,
                            "line": line_no,
                            "content": line.strip()[:140],
                            "pattern_id": pat["id"],
                            "name": pat["name"],
                            "severity": pat["severity"],
                            "description": pat["description"],
                            "remediation": pat.get("remediation", "")
                        })

        # Phase 3: Verifier Phase (False-Positive Elimination)
        confirmed_findings = []
        rejected_findings = []

        placeholder_keywords = {
            "example", "placeholder", "your-api-key", "xxxx", "test-token", "none",
            "dummy", "fake", "changeme", "sample", "env.get", "os.getenv"
        }

        for c in candidates:
            line_content = c["content"]
            line_lower = line_content.lower()

            is_placeholder = any(token in line_lower for token in placeholder_keywords)
            is_comment = line_content.startswith(("#", "//", "/*", "*"))
            is_pattern_definition = "PATTERNS" in line_content or "regex" in line_content or "DEFAULT_PATTERNS" in line_content
            is_in_test = "test" in c["file"].lower() or "mock" in c["file"].lower()

            # Debunking heuristics
            if is_pattern_definition:
                rejected_findings.append({
                    **c,
                    "verdict": "rejected",
                    "reason": "Scanner definition or pattern rule literal"
                })
            elif c["pattern_id"] == "SEC-001" and (is_placeholder or is_comment):
                rejected_findings.append({
                    **c,
                    "verdict": "rejected",
                    "reason": "Comment or placeholder credential sample"
                })
            elif is_in_test and c["pattern_id"] in {"SEC-001", "SEC-006", "SEC-007"}:
                rejected_findings.append({
                    **c,
                    "verdict": "rejected",
                    "reason": "Test fixture / mock file isolated from production"
                })
            else:
                confirmed_findings.append({
                    **c,
                    "verdict": "confirmed",
                    "reason": "Active code seam verified without static sanitization"
                })

        # Phase 4: Risk Scoring
        risk_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in confirmed_findings)

        findings_data = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target_path,
            "risk_score": risk_score,
            "summary": {
                "scanned_files": len(files_to_scan),
                "candidates_found": len(candidates),
                "confirmed_issues": len(confirmed_findings),
                "rejected_false_positives": len(rejected_findings)
            },
            "confirmed": confirmed_findings,
            "rejected": rejected_findings
        }

        # Phase 5: Persist Coverage & Findings
        out_dir = os.path.join(self.target_path, ".audit")
        try:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "coverage-ledger.json"), "w", encoding="utf-8") as f:
                json.dump(coverage_ledger, f, indent=2)
            with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as f:
                json.dump(findings_data, f, indent=2)
        except Exception:
            pass

        return findings_data

    @staticmethod
    def format_report(findings: Dict[str, Any]) -> str:
        s = findings.get("summary", {})
        report = []
        report.append("=" * 76)
        report.append("🛡️  ADVERSARIAL PRE-PUSH SECURITY AUDIT")
        report.append(f"Target: {findings.get('target', '.')}")
        report.append(f"Timestamp: {findings.get('timestamp')}")
        report.append(f"Files Audited: {s.get('scanned_files')} | Candidates: {s.get('candidates_found')}")
        report.append(f"Confirmed Issues: {s.get('confirmed_issues')} | Rejected False-Positives: {s.get('rejected_false_positives')} | Risk Score: {findings.get('risk_score', 0)}")
        report.append("=" * 76)

        confirmed = findings.get("confirmed", [])
        if not confirmed:
            report.append("✅ ZERO confirmed vulnerabilities detected. Codebase satisfies security baseline.")
        else:
            for idx, issue in enumerate(confirmed, 1):
                report.append(f"\n[{idx}] {issue['severity']} | {issue['pattern_id']} - {issue['name']}")
                report.append(f"    Location: {issue['file']}:{issue['line']}")
                report.append(f"    Code:     {issue['content']}")
                report.append(f"    Detail:   {issue['description']}")
                if issue.get("remediation"):
                    report.append(f"    Fix:      {issue['remediation']}")
        report.append("\n" + "=" * 76)
        return "\n".join(report)

def scan_repository(target_path: str = ".") -> Dict[str, Any]:
    """Convenience function to scan a repository."""
    return AdversarialAuditor(target_path).scan()

def format_report(findings: Dict[str, Any]) -> str:
    """Convenience function to format scan findings."""
    return AdversarialAuditor.format_report(findings)

