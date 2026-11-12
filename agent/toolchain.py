"""Build-time inventory. The runtime never refreshes packages or tools."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory():
    packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}\t${Version}\n'], text=True)
    executables = {}
    for name in ('nuclei', 'ffuf', 'chromium', 'agent-browser', 'python', 'java', 'bash', 'curl', 'jq', 'rg'):
        path = shutil.which(name)
        if path:
            executables[name] = {'path': path, 'sha256': digest(path)}
    return {'schema': 1, 'adapter': 25,
        'distribution_packages': dict(line.split('\t', 1) for line in packages.splitlines() if '\t' in line),
        'python_packages': dict(sorted((d.metadata['Name'], d.version) for d in importlib.metadata.distributions())),
        'executables': executables,
        'templates': {str(p.relative_to('/patchriot')): digest(p) for p in Path('/patchriot/templates').rglob('*') if p.is_file()},
        'scanner_archives': {'ZAP_2.17.0_Linux.tar.gz': 'efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a'},
        'limitation': 'Inventory and artifact hashes are provenance evidence, not a malware-free attestation.'}


if __name__ == '__main__':
    Path('/patchriot/toolchain.json').write_text(json.dumps(inventory(), indent=2) + '\n')
