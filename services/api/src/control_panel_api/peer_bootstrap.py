"""One-shot filesystem initialization for the two Dev Control Panel peers.

Runs as root only in the API's init container, with two dedicated volumes.
It has no provider/DB credentials and never prints or shares a private key.
"""

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def directory(path: Path, uid: int, mode: int) -> None:
    if path.is_symlink():
        raise ValueError("Refusing symlink in private peer storage")
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, 1000)
    os.chmod(path, mode)


def initialize() -> None:
    if os.getuid() != 0:
        raise ValueError("Peer volume initialization requires the scoped init container")
    shared = Path("/run/briareus-platform")
    private = Path("/var/lib/briareus-panel")
    directory(shared, 0, 0o750)
    directory(shared / "platform", 1000, 0o750)
    directory(private, 1001, 0o700)
    key_file = private / "signing.key"
    if key_file.is_symlink():
        raise ValueError("Refusing symlink signing key")
    if key_file.exists():
        if not stat.S_ISREG(key_file.stat().st_mode):
            raise ValueError("Invalid signing key storage")
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Ed25519 service key required")
    else:
        key = Ed25519PrivateKey.generate()
        with key_file.open("xb") as output:
            output.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
    os.chown(key_file, 1001, 1000)
    os.chmod(key_file, 0o400)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_file = shared / "panel-signing.pub"
    if public_file.is_symlink():
        raise ValueError("Refusing symlink public key")
    if public_file.exists():
        if public_file.read_bytes() != public:
            raise ValueError("Existing peer pin differs; explicit operator rotation required")
    else:
        with public_file.open("xb") as output:
            output.write(public)
    os.chown(public_file, 0, 1000)
    os.chmod(public_file, 0o440)
    print("Control Panel peer volumes ready; existing service identity preserved")


if __name__ == "__main__":
    initialize()
