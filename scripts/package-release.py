#!/usr/bin/env python3
"""Package a clean checkout, matching protocol source and dependency notices."""

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile


TARGET = "x86_64-unknown-linux-musl"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def add_bytes(archive, name, data, mode=0o644):
    entry = tarfile.TarInfo(name)
    entry.mode = mode
    entry.size = len(data)
    archive.addfile(entry, io.BytesIO(data))


def source_files(repo, paths=()):
    raw = git(repo, "archive", "HEAD", *paths)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for entry in archive:
            if entry.isfile():
                yield entry.name, archive.extractfile(entry).read(), entry.mode
            elif not entry.isdir():
                raise ValueError("Release sources must not contain links or special files")


def license_text(metadata, bundle):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    visited, pending = set(), [root]
    while pending:
        package = pending.pop()
        if package in visited:
            continue
        visited.add(package)
        for dep in nodes[package]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    licenses = {
        (entry["package_name"], entry["package_version"]): entry
        for entry in bundle["third_party_libraries"]
    }
    text = ["Dependency license notices for " + TARGET]
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        if package["id"] not in visited or package["id"] == root:
            continue
        entry = licenses[(package["name"], package["version"])]
        found = [part for part in entry["licenses"] if part.get("text") and "NOT FOUND" not in part["text"]]
        if not found:
            raise ValueError("Missing license text for " + package["name"])
        # Missing alternatives are acceptable only for an OR expression. An AND
        # obligation must retain every text, rather than silently dropping one.
        if len(found) != len(entry["licenses"]) and (" AND " in entry["license"] or " OR " not in entry["license"]):
            raise ValueError("Incomplete license expression for " + package["name"])
        text.append(f"\n{'=' * 72}\n{package['name']} {package['version']} — {entry['license']}")
        text.extend(f"\n{part['license']}\n{part['text']}" for part in found)
    return "\n".join(text).encode()


def package(binary, licenses, output, repo=None):
    repo = repo or Path(__file__).resolve().parents[1]
    protocol_repo = repo.parent / "patchriot-core"
    for checkout in (repo, protocol_repo):
        if git(checkout, "status", "--porcelain", "--untracked-files=no").strip():
            raise ValueError("Build releases from clean committed sources")
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--format-version=1", "--locked", "--filter-platform", TARGET
    ], cwd=repo))
    root = next(item for item in metadata["packages"] if item["id"] == metadata["resolve"]["root"])
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    manifest = {
        "tag": f"v{root['version']}-dev.{commit[:12]}",
        "commit": commit,
        "protocol_commit": git(protocol_repo, "rev-parse", "HEAD").decode().strip(),
        "target": TARGET,
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "sha256": {},
    }
    data = binary.read_bytes()
    # Reject accidentally packaging a macOS binary or another ELF architecture.
    if data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\x3e\x00":
        raise ValueError("Expected a 64-bit little-endian x86-64 ELF binary")
    rust_notices = binary.parent / "rust-notices"
    for name in ("COPYRIGHT-library.html", "licenses/MIT.txt", "licenses/Apache-2.0.txt"):
        if not (rust_notices / name).is_file():
            raise ValueError("Missing Rust runtime notices")
    output.mkdir(parents=True, exist_ok=False)
    sources = list(source_files(repo))
    with tarfile.open(output / "patchriot-relay-linux-x86_64.tar.gz", "w:gz") as archive:
        add_bytes(archive, "patchriot-relay/patchriot-relay", data, 0o755)
        for name, content, mode in sources:
            if name in ("README.md", "LICENSE", "NOTICE") or name.startswith(("agent/", "sandbox/", "deploy/", "licenses/")):
                add_bytes(archive, "patchriot-relay/" + name, content, mode)
        for path in sorted(rust_notices.rglob("*")):
            if path.is_symlink():
                raise ValueError("Runtime notices must not be symlinks")
            if path.is_file():
                add_bytes(archive, "patchriot-relay/licenses/rust/" + path.relative_to(rust_notices).as_posix(), path.read_bytes())
        add_bytes(archive, "patchriot-relay/THIRD-PARTY-LICENSES.txt", license_text(metadata, json.loads(licenses.read_text())))
        add_bytes(archive, "patchriot-relay/BUILD.json", json.dumps(manifest, indent=2).encode() + b"\n")
    with tarfile.open(output / "patchriot-relay-source.tar.gz", "w:gz") as archive:
        for name, content, mode in sources:
            add_bytes(archive, "patchriot-relay/" + name, content, mode)
        for name, content, mode in source_files(protocol_repo, ("crates/protocol",)):
            add_bytes(archive, "patchriot-core/" + name, content, mode)
        # Only the Apache-licensed protocol crate is needed, not the API or UI.
        workspace = b'[workspace]\nmembers = ["crates/protocol"]\nresolver = "3"\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n\n[workspace.lints.clippy]\nall = "warn"\n'
        add_bytes(archive, "patchriot-core/Cargo.toml", workspace)
    for path in sorted(output.glob("*.tar.gz")):
        manifest["sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in manifest["sha256"].items()))
    (output / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
            handle.write("tag=" + manifest["tag"] + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: package-release.py BINARY LICENSE_BUNDLE OUTPUT_DIRECTORY")
    package(*(Path(arg).resolve() for arg in sys.argv[1:]))
