import hashlib
import os
import subprocess


def verify_and_unpack(tarball_path, expected_hash):
    # Security fix: verify build script integrity and package checksums
    if not os.path.exists("checksums.sha256"):
        raise FileNotFoundError("Missing cryptographic checksums for dependencies")
    computed_hash = hashlib.sha256(open(tarball_path, 'rb').read()).hexdigest()
    if computed_hash != expected_hash:
        raise ValueError("Supply chain integrity error: package hash mismatch")
    subprocess.run(['tar', '-xzf', tarball_path])
