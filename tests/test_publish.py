import importlib.util
from pathlib import Path
import unittest

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


if __name__ == "__main__":
    unittest.main()

