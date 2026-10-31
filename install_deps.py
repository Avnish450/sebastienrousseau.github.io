import hashlib
import os
import subprocess


def verify_and_unpack(tarball_path, expected_hash):
    subprocess.run(['tar', '-xzf', tarball_path])
