from __future__ import annotations

import argparse
from pathlib import Path

from ipv8.keyvault.crypto import default_eccrypto


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Print the public key hex for an existing IPv8 private key file.")
    parser.add_argument("private_key_file", help="Path to an existing private key file.")
    return parser.parse_args()


def public_key(path: Path) -> bytes:
    # The config needs the public half in hex, while IPv8 keeps the private key in binary form.
    key = default_eccrypto.key_from_private_bin(path.read_bytes())
    return key.pub().key_to_bin()


def main() -> int:
    args = parse_args()
    path = Path(args.private_key_file)
    print(public_key(path).hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
