#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import difflib
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


ALLOWED_TARGET_PREFIXES = (
    "backend/app/",
    "frontend/",
    "docs/",
    "scripts/",
    "README.md",
    "requirements.txt",
    "start.sh",
    "start.command",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.cn.yml",
)
SKIP_PARTS = {".git", ".venv", "__pycache__", "node_modules", "backend/data"}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".css",
    ".html",
    ".md",
    ".txt",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".sh",
    ".command",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a ZhuWei structured .update from two source directories.")
    parser.add_argument("--old", required=True, help="Old project directory")
    parser.add_argument("--new", required=True, help="New project directory")
    parser.add_argument("--output", required=True, help="Output .update path")
    parser.add_argument("--summary", required=True, help="Human-readable update summary")
    parser.add_argument("--mode", choices=["patch", "replace"], default="patch", help="How to encode modified files")
    parser.add_argument("--from-version", default="", help="Optional source version label for humans")
    parser.add_argument("--to-version", default="", help="Optional target version label for humans")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt output with AES-256-GCM")
    parser.add_argument("--key", default=os.getenv("UPDATE_ENCRYPTION_KEY", ""), help="Encryption key: base64, hex, or passphrase")
    parser.add_argument("--kid", default="", help="Optional key id")
    args = parser.parse_args()

    old_root = Path(args.old).resolve()
    new_root = Path(args.new).resolve()
    output = Path(args.output).resolve()
    if not old_root.is_dir() or not new_root.is_dir():
        raise SystemExit("--old and --new must be directories")
    if output.suffix.lower() != ".update":
        raise SystemExit("--output must end with .update")

    with tempfile.TemporaryDirectory() as tmp:
        package_dir = Path(tmp) / "package"
        package_dir.mkdir()
        manifest = _build_package(
            old_root,
            new_root,
            package_dir,
            summary=args.summary,
            mode=args.mode,
            from_version=args.from_version,
            to_version=args.to_version,
        )
        if not manifest["operations"]:
            raise SystemExit("no allowed changes found")
        (package_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        payload = Path(tmp) / "payload.zip"
        _zip_dir(package_dir, payload)
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


def _build_package(
    old_root: Path,
    new_root: Path,
    package_dir: Path,
    *,
    summary: str,
    mode: str,
    from_version: str = "",
    to_version: str = "",
) -> dict:
    old_files = _collect_files(old_root)
    new_files = _collect_files(new_root)
    deleted = sorted(set(old_files) - set(new_files))
    if deleted:
        raise SystemExit("delete operations are not supported by this generator: " + ", ".join(deleted[:10]))

    operations = []
    for rel in sorted(set(new_files) - set(old_files)):
        source_rel = f"files/{rel}"
        _copy_payload(new_root / rel, package_dir / source_rel)
        after_sha = _sha256_file(new_root / rel)
        operations.append({
            "action": "add",
            "path": rel,
            "source": source_rel,
            "before_sha256": "absent",
            "source_sha256": after_sha,
            "after_sha256": after_sha,
            "description": f"add {rel}",
        })

    for rel in sorted(set(old_files) & set(new_files)):
        old_text = _read_text(old_root / rel)
        new_text = _read_text(new_root / rel)
        if old_text == new_text:
            continue
        if mode == "replace":
            source_rel = f"files/{rel}"
            _copy_payload(new_root / rel, package_dir / source_rel)
            before_sha = _sha256_file(old_root / rel)
            after_sha = _sha256_file(new_root / rel)
            operations.append({
                "action": "replace",
                "path": rel,
                "source": source_rel,
                "before_sha256": before_sha,
                "source_sha256": after_sha,
                "after_sha256": after_sha,
                "description": f"replace {rel}",
            })
        else:
            patch_rel = f"patches/{_patch_name(rel)}.patch"
            patch_text = "".join(
                difflib.unified_diff(
                    old_text.splitlines(keepends=True),
                    new_text.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                )
            )
            target = package_dir / patch_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            patch_bytes = patch_text.encode("utf-8")
            target.write_bytes(patch_bytes)
            operations.append({
                "action": "patch",
                "path": rel,
                "patch": patch_rel,
                "before_sha256": _sha256_file(old_root / rel),
                "patch_sha256": hashlib.sha256(patch_bytes).hexdigest(),
                "after_sha256": _sha256_file(new_root / rel),
                "description": f"patch {rel}",
            })
    manifest = {"schema_version": "1", "summary": summary, "operations": operations}
    if from_version:
        manifest["from_version"] = from_version
    if to_version:
        manifest["to_version"] = to_version
    return manifest


def _collect_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not _allowed(rel):
            continue
        _ensure_text_file(path, rel)
        files[rel] = path
    return files


def _allowed(rel: str) -> bool:
    parts = rel.split("/")
    if any(part in SKIP_PARTS for part in parts):
        return False
    if rel.startswith("backend/data/"):
        return False
    return any(rel == prefix or rel.startswith(prefix) for prefix in ALLOWED_TARGET_PREFIXES)


def _ensure_text_file(path: Path, rel: str) -> None:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        raise SystemExit(f"unsupported file type for update: {rel}")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise SystemExit(f"file too large for update: {rel}")
    _read_text(path)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"file is not UTF-8 text: {path}") from exc


def _copy_payload(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _patch_name(rel: str) -> str:
    return rel.replace("/", "__").replace("\\", "__")


def _zip_dir(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source).as_posix())


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
