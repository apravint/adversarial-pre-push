import os
import tempfile
import unittest
from adversarial_pre_push.audit import AdversarialAuditor
from adversarial_pre_push.cli import install_git_hook

class TestAdversarialAuditor(unittest.TestCase):
    def test_clean_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "app.py")
            with open(test_file, "w") as f:
                f.write("def add(a, b):\n    return a + b\n")

            auditor = AdversarialAuditor(tmpdir)
            findings = auditor.scan()
            self.assertEqual(findings["summary"]["confirmed_issues"], 0)
            self.assertEqual(findings["risk_score"], 0)

    def test_detect_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "leak.py")
            with open(test_file, "w") as f:
                f.write('API_KEY = "live_secret_key_1234567890abcdef"\n')

            auditor = AdversarialAuditor(tmpdir)
            findings = auditor.scan()
            self.assertEqual(findings["summary"]["confirmed_issues"], 1)
            self.assertEqual(findings["confirmed"][0]["pattern_id"], "SEC-001")
            self.assertEqual(findings["confirmed"][0]["severity"], "CRITICAL")

    def test_verifier_debunks_placeholder(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "config.py")
            with open(test_file, "w") as f:
                f.write('API_KEY = "your-api-key-here-placeholder"\n')

            auditor = AdversarialAuditor(tmpdir)
            findings = auditor.scan()
            self.assertEqual(findings["summary"]["confirmed_issues"], 0)
            self.assertGreaterEqual(findings["summary"]["rejected_false_positives"], 1)
            self.assertEqual(findings["rejected"][0]["verdict"], "rejected")

    def test_install_git_hook(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = os.path.join(tmpdir, ".git")
            os.makedirs(git_dir)

            success = install_git_hook(tmpdir)
            self.assertTrue(success)
            hook_path = os.path.join(git_dir, "hooks", "pre-push")
            self.assertTrue(os.path.exists(hook_path))
            self.assertTrue(os.access(hook_path, os.X_OK))

if __name__ == "__main__":
    unittest.main()
