# 🛡️ adversarial-pre-push

[![CI](https://github.com/apravint/adversarial-pre-push/actions/workflows/ci.yml/badge.svg)](https://github.com/apravint/adversarial-pre-push/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)

> **Zero-dependency, 6-phase adversarial security auditor and git pre-push gate.**  
> Features explicit dual-stage Hunter (candidate extraction) and Verifier (false-positive debunking) architecture.

---

## 💡 Why adversarial-pre-push?

Traditional static analysis tools either produce excessive false positives or miss active code injection seams. `adversarial-pre-push` is designed with an adversarial auditing mindset:

1. **Phase 1: Reconnaissance & Ledger:** Maps codebase surface and logs a reproducible `coverage-ledger.json`.
2. **Phase 2: Hunter Phase:** Discovers candidate vulnerability seams (tokens, unsanitized shell calls, eval, unsafe deserialization, TLS bypasses).
3. **Phase 3: Verifier Phase:** An independent verification pass debunks placeholder credentials, test suites, scanner definitions, and comments.
4. **Phase 4: Risk Scoring:** Computes weighted severity scores (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
5. **Phase 5: Artifact Persistence:** Exports structured `.audit/findings.json` and human-readable terminal reports.
6. **Phase 6: Git Pre-Push Gate:** Blocks pushes if unresolved `HIGH` or `CRITICAL` issues are detected.

---

## 🚀 Quick Start

### Installation

```bash
pip install adversarial-pre-push
```

Or run directly from source:
```bash
git clone https://github.com/apravint/adversarial-pre-push.git
cd adversarial-pre-push
pip install -e .
```

### Install Git Hook

Automatically install the pre-push hook into any repository:

```bash
adversarial-pre-push install-hook /path/to/repo
```

Now, every time you run `git push`, the hook runs automatically and halts execution if critical vulnerabilities are detected.

### Manual Security Scan

```bash
# Scan current directory with terminal report
adversarial-pre-push audit .

# Scan with structured JSON output
adversarial-pre-push audit /path/to/project --json

# Fail only on CRITICAL findings
adversarial-pre-push audit . --fail-on CRITICAL
```

---

## 🔍 Auditing Coverage Matrix

| Rule ID | Name | Severity | Heuristic & Pattern |
|---|---|---|---|
| `SEC-001` | Hardcoded Secret / API Token | `CRITICAL` | High-entropy tokens, private keys, API secrets |
| `SEC-002` | Unsafe Shell Injection Seam | `HIGH` | `shell=True`, unsanitized `os.system()`, `os.popen()` |
| `SEC-003` | Dynamic Code Evaluation | `CRITICAL` | Arbitrary code execution via `eval()`, `exec()` |
| `SEC-004` | Insecure Deserialization | `HIGH` | Untrusted `pickle.load` / unsafe `yaml.load` |
| `SEC-005` | Disabled TLS Verification | `HIGH` | `verify=False`, disabled SSL handshakes |
| `SEC-006` | Insecure Temporary File Path | `MEDIUM` | Predictable `/tmp/` race/symlink vulnerabilities |
| `SEC-007` | Hardcoded Private User Path | `LOW` | Leaked `/home/<user>/` paths breaking portability |

---

## 🧪 Testing

```bash
pytest tests/
```

---

## 📄 License

MIT License. Crafted with ❤️ by [apravint](https://github.com/apravint).
