"""Check the reviewed public-verification paths behind two audit exceptions."""
import hashlib
import json
from pathlib import Path
import subprocess


EXPECTED_PARENTS = {
    ('rsa', '0.9.10'): {('jsonwebtoken', '10.4.0')},
    ('crypto-bigint', '0.5.5'): {('elliptic-curve', '0.13.8')},
    ('elliptic-curve', '0.13.8'): {
        ('ecdsa', '0.16.9'), ('primeorder', '0.13.6'),
        ('p256', '0.13.2'), ('p384', '0.13.1'),
    },
    ('ecdsa', '0.16.9'): {('p256', '0.13.2'), ('p384', '0.13.1')},
    ('primeorder', '0.13.6'): {('p256', '0.13.2'), ('p384', '0.13.1')},
    ('p256', '0.13.2'): {('jsonwebtoken', '10.4.0')},
    ('p384', '0.13.1'): {('jsonwebtoken', '10.4.0')},
    ('jsonwebtoken', '10.4.0'): {('nearai-inference-sdk', '0.2.1')},
    ('nearai-inference-sdk', '0.2.1'): {('patchriot-relay', '0.0.1')},
}
NVIDIA_SOURCE_SHA256 = 'be079f71e31e4a3ac4e90fe142495694cf0c82f305cde5f0ad1f2ab318541914'


def verify(metadata):
    packages = {package['id']: package for package in metadata['packages']}
    identities = {key: (package['name'], package['version']) for key, package in packages.items()}
    for name, allowed in {
        'rsa': {'0.9.10'},
        'crypto-bigint': {'0.5.5', '0.7.10'},
        'k256': {'0.14.0'},
    }.items():
        if {version for package, version in identities.values() if package == name} != allowed:
            raise ValueError(f'Audit exception requires renewed version review for {name}')
    parents = {identity: set() for identity in identities.values()}
    for node in metadata['resolve']['nodes']:
        for dependency in node['dependencies']:
            parents[identities[dependency]].add(identities[node['id']])
    for package, expected in EXPECTED_PARENTS.items():
        if parents.get(package) != expected:
            raise ValueError(f'Audit exception requires renewed review for {package}')
    sdk = next(package for package in packages.values()
               if (package['name'], package['version']) == ('nearai-inference-sdk', '0.2.1'))
    if sdk['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
        raise ValueError('Audit exception requires the reviewed registry SDK')
    source = Path(sdk['manifest_path']).parent / 'src/nvidia.rs'
    if hashlib.sha256(source.read_bytes()).hexdigest() != NVIDIA_SOURCE_SHA256:
        raise ValueError('Reviewed ES384 verification implementation changed')


if __name__ == '__main__':
    metadata = subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version=1'], text=True)
    verify(json.loads(metadata))
    print('Reviewed SDK public-verification dependency paths match the audit exceptions.')
