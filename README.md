# DADAAPI Routes

This repository publishes the signed encrypted route bundle consumed by the DADAAPI desktop client. Public contents are limited to `manifest.json`, `routes.sig`, and `routes.enc`; upstream subscription URLs, node credentials, signing private keys, and encryption keys are held only in GitHub Actions secrets.

The scheduled publisher accepts Clash YAML, keeps compatible overseas Hysteria2 nodes, anonymizes route labels, encrypts the resulting URI list with XChaCha20-Poly1305, and signs the manifest with Ed25519. It publishes the desktop client's v2 wire format (`DADAR002`, `dadaapi-routes/v2`, and `schemaVersion: 2`). The exact GitHub commit is then fast-forwarded to Gitee; divergent mirrors are never force-pushed.
