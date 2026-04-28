#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a structured ZhuWei .update package.")
    parser.add_argument("source", help="Directory containing manifest.json, patches/, and files/.")
    parser.add_argument("output", help="Output .update file")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the structured zip with AES-256-GCM")
    parser.add_argument("--key", default=os.getenv("UPDATE_ENCRYPTION_KEY", ""), help="AES key: base64, hex, or passphrase")
    parser.add_argument("--kid", default="", help="Optional key id stored in the envelope")
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        raise SystemExit(f"source directory not found: {source}")
    if not (source / "manifest.json").is_file():
        raise SystemExit("source directory must contain manifest.json")
    if output.suffix.lower() != ".update":
        raise SystemExit("output filename must end with .update")

    with tempfile.TemporaryDirectory() as tmp:
        payload = Path(tmp) / "payload.zip"
        _zip_source(source, payload)
        if args.encrypt:
            key = _key_bytes(args.key)
            if not key:
                raise SystemExit("--encrypt requires --key or UPDATE_ENCRYPTION_KEY")
            _write_envelope(payload.read_bytes(), output, key=key, kid=args.kid)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(payload, output)
    print(f"created {output}")
    return 0


def _zip_source(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(source).as_posix()
            if rel.startswith(".") or "/." in rel:
                continue
            zf.write(path, rel)


def _write_envelope(payload: bytes, output: Path, *, key: bytes, kid: str = "") -> None:
    nonce = secrets.token_bytes(12)
    aad = b"zhuwei-update-v1"
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
    envelope = {
        "format": "zhuwei.encrypted.update",
        "version": 1,
        "alg": "AES-256-GCM",
        "kid": kid,
        "aad": aad.decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def _key_bytes(value: str) -> bytes:
    value = (value or "").strip()
    if not value:
        return b""
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == 32:
            return decoded
    except ValueError:
        pass
    if len(value) == 64:
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    return hashlib.sha256(value.encode("utf-8")).digest()


if __name__ == "__main__":
    sys.exit(main())
