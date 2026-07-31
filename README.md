# DADAAPI Routes

This repository publishes the signed encrypted route bundle consumed by the DADAAPI desktop client. Public contents are limited to `manifest.json`, `routes.sig`, and `routes.enc`; upstream subscription URLs, node credentials, signing private keys, and encryption keys are held only in GitHub Actions secrets.

The scheduled publisher accepts Clash YAML, keeps compatible overseas Hysteria2 nodes, anonymizes route labels, encrypts the resulting URI list with XChaCha20-Poly1305, and signs the manifest with Ed25519. The exact GitHub commit is then mirrored to Gitee.

