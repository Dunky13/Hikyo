# Hikyo

Fully open-source secrets and configuration across environments, with validation,
explicit per-environment values, and no enterprise tier.

Hikyo is a self-hosted control plane for developers and platform engineers. It
ships as one Go binary, supports SQLite and PostgreSQL, and treats every value as
explicitly `set` or `absent` in each environment.

The project is under active `0.x` development. Interfaces are not frozen until
the `1.0.0` release gate passes.

## Fully open, no enterprise tier

Every capability required to run Hikyo in production is and will remain open
source; there is no `/ee` directory and there will never be one.

The full commitment, including how it may be amended, is in
[GOVERNANCE.md](./GOVERNANCE.md#fully-open-pledge).

## Documentation

- [Security policy](./SECURITY.md)
- [Support policy](./SUPPORT.md)
- [Governance](./GOVERNANCE.md)
- [Trademark policy](./TRADEMARK.md)
- [Contributing](./CONTRIBUTING.md)

## License

Hikyo is licensed under the [Mozilla Public License 2.0](./LICENSE).
