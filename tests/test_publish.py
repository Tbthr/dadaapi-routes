import base64
import importlib.util
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

MODULE_PATH = Path(__file__).parents[1] / "publisher" / "publish.py"
SPEC = importlib.util.spec_from_file_location("publisher", MODULE_PATH)
publisher = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def test_converts_only_compatible_overseas_hysteria2(self):
        source = b"""
proxies:
  - {name: SG, type: hysteria2, server: example.com, port: 443, password: secret, sni: edge.example.com}
  - {name: HK, type: hysteria2, server: hk.example.com, port: 443, password: secret}
  - {name: US, type: trojan, server: us.example.com, port: 443, password: secret}
"""
        routes = publisher.convert_clash_subscription(source)
        self.assertEqual(len(routes), 1)
        self.assertTrue(routes[0].startswith("hysteria2://"))
        self.assertIn("#route-1", routes[0])
        self.assertNotIn("SG", routes[0])

    def test_rejects_non_clash_payload(self):
        with self.assertRaises(RuntimeError):
            publisher.convert_clash_subscription(b"hello: world")

    def test_emits_desktop_v2_route_bundle(self):
        encryption_key = bytes(range(32))
        signing_key = Ed25519PrivateKey.generate()
        generated_at = publisher.datetime(2026, 8, 1, tzinfo=publisher.timezone.utc)
        files = publisher.build_bundle(
            ["hysteria2://password@example.com:443?sni=example.com#route-1"],
            encryption_key,
            signing_key,
            "v1",
            generated_at,
        )

        manifest = json.loads(files["manifest.json"])
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(files["routes.enc"][:8], b"DADAR002")
        self.assertEqual(manifest["routeSize"], len(files["routes.enc"]))
        self.assertEqual(
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                files["routes.enc"][32:],
                b"dadaapi-routes/v2",
                files["routes.enc"][8:32],
                encryption_key,
            ),
            b"hysteria2://password@example.com:443?sni=example.com#route-1\n",
        )
        signing_key.public_key().verify(
            base64.b64decode(files["routes.sig"]), files["manifest.json"]
        )


if __name__ == "__main__":
    unittest.main()
