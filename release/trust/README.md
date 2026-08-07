# Production trust bootstrap

This directory intentionally contains no production key yet. The locked signing
ADR requires both key pairs to be generated with networking disabled and the
encrypted private keys copied to separate offline media. CI fixture keys live
only in temporary directories and cannot authorize a release.

Before the first `v*` tag, follow `docs/release/signing.md`. Commit only:

- `root.json`, `recovery-1.pub`, and the initial primary `.pub` file;
- `metadata.json` and its recovery-root `metadata.sigstore.json` bundle.

Never commit `*.key`, decrypted key material, or a signing passphrase. Release
CI refuses to run until the production bootstrap files exist and verify.
