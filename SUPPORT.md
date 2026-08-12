# Support policy

## Supported version

Hikyo supports exactly one version: the latest patch release of the latest minor
of the latest major.

Security fixes land on that version and only that version. The previous minor is
end-of-life on the same day a new minor is released, and that end of life is
stated in the new minor's release notes. Prereleases are never supported.

## No backports

Hikyo does not maintain backport branches. An urgent security fix may therefore
require a feature-bearing minor upgrade. The project keeps that upgrade path
cheap through a single binary and roll-forward database migrations.

Patch releases are made on demand. Minor releases are milestone-driven, not tied
to a calendar. The security response targets in [SECURITY.md](./SECURITY.md) are
the response commitment; this policy does not promise indefinite maintenance.

Long-term support is a future decision whose trigger is a maintainer team large
enough to fund backports. It is not offered before then.
