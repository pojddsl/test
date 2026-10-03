import subprocess
import tempfile
import unittest
from pathlib import Path

from repo_audit import scan_repo


class RepoAuditTests(unittest.TestCase):
    def make_repo(self) -> Path:
        directory = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(directory)], check=True)
        return directory

    def track(self, root: Path, *names: str) -> None:
        subprocess.run(["git", "-C", str(root), "add", *names], check=True)

    def test_clean_tracked_file_has_no_findings(self) -> None:
        root = self.make_repo()
        (root / "README.md").write_text("A small example project.\n", encoding="utf-8")
        self.track(root, "README.md")

        self.assertEqual(scan_repo(root), [])

    def test_detects_tracked_secret_but_ignores_untracked_file(self) -> None:
        root = self.make_repo()
        (root / "config.py").write_text(
            'API_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8"
        )
        (root / "untracked.txt").write_text(
            'TOKEN = "ghp_123456789012345678901234567890123456"\n',
            encoding="utf-8",
        )
        self.track(root, "config.py")

        findings = scan_repo(root)
        self.assertEqual([(item.path, item.rule) for item in findings], [("config.py", "aws-access-key")])

    def test_detects_private_key_and_skips_binary_file(self) -> None:
        root = self.make_repo()
        (root / "key.txt").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8"
        )
        (root / "image.bin").write_bytes(b"\0AKIA1234567890ABCDEF")
        self.track(root, "key.txt", "image.bin")

        findings = scan_repo(root)
        self.assertEqual([(item.path, item.rule) for item in findings], [("key.txt", "private-key")])


if __name__ == "__main__":
    unittest.main()
