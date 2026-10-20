"""
adversarial-pre-push: 6-phase adversarial vulnerability auditing git hook with separated hunter and verifier agents.
"""

__version__ = "0.1.0"

from .audit import AdversarialAuditor, scan_repository, format_report

__all__ = ["AdversarialAuditor", "scan_repository", "format_report"]
