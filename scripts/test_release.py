"""Release checks use tiny owned repositories; no network or publishing."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("package-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="patchriot-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "patchriot-relay"
        self.protocol = self.root / "patchriot-core"
        for repo, files in [(self.repo, {
            "README.md": "Relay", "LICENSE": "Relay license", "src/main.rs": "fn main() {}",
            "agent/adapter.py": "# adapter", ".gitignore": ".env\n",
        }), (self.protocol, {
            "crates/protocol/src/lib.rs": "// wire types",
            "crates/protocol/LICENSE": "Protocol license",
            "crates/server/private.rs": "PRIVATE SERVER SOURCE",
        })]:
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for name, content in files.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "Owned release fixture"], check=True)
        (self.repo / ".env").write_text("LOCAL_CANARY_NOT_FOR_RELEASE")
        self.binary = self.root / "relay"
        self.binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(44))
        for name in ("COPYRIGHT-library.html", "licenses/MIT.txt", "licenses/Apache-2.0.txt"):
            notice = self.root / "rust-notices" / name
            notice.parent.mkdir(parents=True, exist_ok=True)
            notice.write_text("Runtime notice fixture")
        self.bundle = {"third_party_libraries": [{
            "package_name": "wire", "package_version": "1.0.0", "license": "MIT",
            "licenses": [{"license": "MIT", "text": "Permission notice fixture"}],
        }]}
        self.metadata = {
            "resolve": {"root": "relay", "nodes": [
                {"id": "relay", "deps": [{"pkg": "wire", "dep_kinds": [{"kind": None}]}]},
                {"id": "wire", "deps": []},
            ]},
            "packages": [
                {"id": "relay", "name": "patchriot-relay", "version": "0.0.1"},
                {"id": "wire", "name": "wire", "version": "1.0.0"},
            ],
        }
        self.licenses = self.root / "licenses.json"
        self.licenses.write_text(json.dumps(self.bundle))
        self.output = self.root / "dist"

    def build(self):
        original = subprocess.check_output

        def command(args, **kwargs):
            if args[0] == "cargo":
                self.assertIn("--locked", args)
                return json.dumps(self.metadata).encode()
            if args[0] == "rustc":
                return "rustc fixture\n"
            return original(args, **kwargs)

        with patch.object(subprocess, "check_output", side_effect=command), contextlib.redirect_stdout(io.StringIO()):
            release.package(self.binary, self.licenses, self.output, self.repo)

    def test_download_contains_notices_executable_and_matching_source_without_private_files(self):
        self.build()
        with tarfile.open(self.output / "patchriot-relay-linux-x86_64.tar.gz") as archive:
            self.assertEqual(archive.getmember("patchriot-relay/patchriot-relay").mode, 0o755)
            self.assertIn(b"Permission notice fixture", archive.extractfile("patchriot-relay/THIRD-PARTY-LICENSES.txt").read())
            self.assertIn("patchriot-relay/agent/adapter.py", archive.getnames())
            self.assertIn("patchriot-relay/licenses/rust/COPYRIGHT-library.html", archive.getnames())
            self.assertNotIn("patchriot-relay/.env", archive.getnames())
        with tarfile.open(self.output / "patchriot-relay-source.tar.gz") as archive:
            self.assertIn("patchriot-core/crates/protocol/LICENSE", archive.getnames())
            self.assertNotIn("patchriot-core/crates/server/private.rs", archive.getnames())
            self.assertNotIn("patchriot-relay/.env", archive.getnames())
        manifest = json.loads((self.output / "release.json").read_text())
        self.assertEqual(manifest["commit"], release.git(self.repo, "rev-parse", "HEAD").decode().strip())
        for name, digest in manifest["sha256"].items():
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_dirty_source_is_refused(self):
        (self.repo / "src/main.rs").write_text("changed")
        with self.assertRaisesRegex(ValueError, "clean committed"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_wrong_platform_is_refused(self):
        self.binary.write_bytes(b"not an ELF")
        with self.assertRaisesRegex(ValueError, "ELF"):
            self.build()

    def test_missing_runtime_notices_are_refused(self):
        (self.root / "rust-notices/COPYRIGHT-library.html").unlink()
        with self.assertRaisesRegex(ValueError, "Rust runtime notices"):
            self.build()

    def test_missing_required_license_stops_packaging(self):
        entry = self.bundle["third_party_libraries"][0]
        entry["licenses"][0]["text"] = "NOT FOUND"
        with self.assertRaisesRegex(ValueError, "Missing license"):
            release.license_text(self.metadata, self.bundle)
        entry["license"] = "MIT AND Apache-2.0"
        entry["licenses"].append({"license": "Apache-2.0", "text": "Second notice"})
        with self.assertRaisesRegex(ValueError, "Incomplete license"):
            release.license_text(self.metadata, self.bundle)

    def test_unlinked_platform_and_build_dependencies_do_not_change_runtime_notices(self):
        self.metadata["packages"].append({"id": "compiler", "name": "compiler", "version": "1"})
        self.metadata["resolve"]["nodes"][0]["deps"].append({"pkg": "compiler", "dep_kinds": [{"kind": "build"}]})
        self.assertIn(b"Permission notice fixture", release.license_text(self.metadata, self.bundle))


if __name__ == "__main__":
    unittest.main()
