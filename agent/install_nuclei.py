"""Build-time installer; the runtime never updates binaries or templates."""
import hashlib
import io
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = "3.11.1"
RELEASES = {
    "x86_64": ("amd64", "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6"),
    "aarch64": ("arm64", "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07"),
}


def main():
    arch, expected = RELEASES[platform.machine()]
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{VERSION}/nuclei_{VERSION}_linux_{arch}.zip"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(160 * 1024 * 1024 + 1)
    if len(data) > 160 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("Nuclei release checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        # Never extract paths or follow links from an archive.
        binary = Path("/usr/local/bin/nuclei")
        binary.write_bytes(archive.read("nuclei"))
        binary.chmod(0o755)
        license_file = Path("/usr/share/licenses/nuclei/LICENSE.md")
        license_file.parent.mkdir(parents=True, exist_ok=True)
        license_file.write_bytes(archive.read("LICENSE.md"))


if __name__ == "__main__":
    main()
