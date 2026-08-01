#!/usr/bin/env python3
"""Fetch a Clash subscription and publish a signed encrypted route bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

ROUTE_MAGIC = b"DADAR002"
ROUTE_AAD = b"dadaapi-routes/v2"
ROUTE_SCHEMA_VERSION = 2
MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024
ALLOWED_REDIRECTS = 5
EXPIRES_AFTER = timedelta(hours=72)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("public"))
    parser.add_argument("--source-file", type=Path)
    args = parser.parse_args()

    source = args.source_file.read_bytes() if args.source_file else fetch_subscription()
    routes = convert_clash_subscription(source)
    if not routes:
        raise RuntimeError("subscription contains no compatible overseas Hysteria2 nodes")

    encryption_key = decode_encryption_key(required_env("ROUTE_ENCRYPTION_KEY_B64"))
    signing_key = load_signing_key(required_env("ROUTE_SIGNING_PRIVATE_KEY_PEM"))
    key_id = os.environ.get("ROUTE_KEY_ID", "v1").strip()
    if not key_id:
        raise RuntimeError("ROUTE_KEY_ID cannot be empty")

    generated_at = datetime.now(timezone.utc).replace(microsecond=0)
    files = build_bundle(routes, encryption_key, signing_key, key_id, generated_at)
    atomic_publish(args.output, files)
    print(f"published {len(routes)} compatible routes as {generated_at.strftime('%Y%m%dT%H%M%SZ')}")


def build_bundle(
    routes: list[str],
    encryption_key: bytes,
    signing_key: Ed25519PrivateKey,
    key_id: str,
    generated_at: datetime,
) -> dict[str, bytes]:
    plaintext = ("\n".join(routes) + "\n").encode()
    nonce = os.urandom(24)
    encrypted = ROUTE_MAGIC + nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, ROUTE_AAD, nonce, encryption_key
    )
    manifest = {
        "schemaVersion": ROUTE_SCHEMA_VERSION,
        "version": generated_at.strftime("%Y%m%dT%H%M%SZ"),
        "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
        "expiresAt": (generated_at + EXPIRES_AFTER).isoformat().replace("+00:00", "Z"),
        "routeFile": "routes.enc",
        "routeSha256": hashlib.sha256(encrypted).hexdigest(),
        "routeSize": len(encrypted),
        "encryption": "xchacha20poly1305",
        "keyId": key_id,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    signature = base64.b64encode(signing_key.sign(manifest_bytes)) + b"\n"
    return {
        "manifest.json": manifest_bytes,
        "routes.sig": signature,
        "routes.enc": encrypted,
    }


def fetch_subscription() -> bytes:
    url = required_env("UPSTREAM_SUBSCRIPTION_URL")
    if not url.startswith("https://"):
        raise RuntimeError("UPSTREAM_SUBSCRIPTION_URL must use HTTPS")
    session = requests.Session()
    response = session.get(
        url,
        headers={"User-Agent": "Clash.Meta"},
        timeout=(10, 30),
        allow_redirects=True,
        stream=True,
    )
    response.raise_for_status()
    if len(response.history) > ALLOWED_REDIRECTS:
        raise RuntimeError("subscription exceeded redirect limit")
    if any(not item.url.startswith("https://") for item in [*response.history, response]):
        raise RuntimeError("subscription redirect chain must remain HTTPS")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(64 * 1024):
        size += len(chunk)
        if size > MAX_SUBSCRIPTION_BYTES:
            raise RuntimeError("subscription exceeds 8 MiB")
        chunks.append(chunk)
    return b"".join(chunks)


def convert_clash_subscription(payload: bytes) -> list[str]:
    config = yaml.safe_load(payload.decode("utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("proxies"), list):
        raise RuntimeError("upstream is not a Clash YAML subscription")
    routes: list[str] = []
    for proxy in config["proxies"]:
        if not isinstance(proxy, dict) or str(proxy.get("type", "")).lower() not in {
            "hysteria2", "hy2"
        }:
            continue
        name = str(proxy.get("name", "")).strip()
        if excluded_name(name):
            continue
        routes.append(hysteria2_uri(proxy, f"route-{len(routes) + 1}"))
    return routes


def hysteria2_uri(proxy: dict, anonymous_name: str) -> str:
    server = str(proxy.get("server", "")).strip()
    password = str(proxy.get("password") or proxy.get("auth") or "")
    port = int(proxy.get("port", 0))
    if not server or not password or not 1 <= port <= 65535:
        raise RuntimeError("Hysteria2 node is missing a required field")
    try:
        host = f"[{server}]" if ipaddress.ip_address(server).version == 6 else server
    except ValueError:
        host = server
    query = [f"sni={quote(str(proxy.get('sni') or server), safe='')}"]
    if proxy.get("skip-cert-verify") is True:
        query.append("insecure=1")
    obfs = str(proxy.get("obfs", "")).lower()
    if obfs and obfs != "none":
        if obfs != "salamander":
            raise RuntimeError("unsupported Hysteria2 obfuscation")
        obfs_password = str(proxy.get("obfs-password") or "")
        if not obfs_password:
            raise RuntimeError("Hysteria2 obfuscation password is missing")
        query.extend(["obfs=salamander", f"obfs-password={quote(obfs_password, safe='')}"] )
    return (
        f"hysteria2://{quote(password, safe='')}@{host}:{port}?"
        f"{'&'.join(query)}#{anonymous_name}"
    )


def excluded_name(name: str) -> bool:
    lowered = name.lower()
    tokens = {token for token in __import__("re").split(r"[^a-z0-9]+", lowered) if token}
    return (
        any(term in name for term in ("香港", "港", "中国大陆", "大陆", "国内"))
        or "hong kong" in lowered
        or "mainland china" in lowered
        or "hk" in tokens
        or "cn" in tokens
    )


def decode_encryption_key(value: str) -> bytes:
    key = base64.b64decode(value, validate=True)
    if len(key) != 32:
        raise RuntimeError("route encryption key must contain 32 bytes")
    return key


def load_signing_key(value: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(value.replace("\\n", "\n").encode(), None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("route signing key must be Ed25519")
    return key


def atomic_publish(output: Path, files: dict[str, bytes]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        with tempfile.NamedTemporaryFile(dir=output, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(output / name)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()
