# Stream D3 summary — complete Compose demo run (#63)

## Fixed

- Corrected the demo's round-trip oracle to compare delivered bytes with the
  stored value, `strings.TrimSpace(input)`, as required by the schema ADR.
- Matched Go's Unicode `strings.TrimSpace` whitespace set in the script and
  retained `allow_empty: true`, so empty and whitespace-only inputs are valid
  post-trim corpus values.
- Documented that the leading- and trailing-whitespace corpus rows prove trim
  is the only transformation; all remaining stored bytes are delivered exactly.

No Go code or API/datastore bypass changed.

## Final demo status

Command:

```text
GOCACHE=/tmp/hikyo-go-build-cache ./scripts/compose-demo.sh
```

Passed hierarchy creation, 20 representable corpus values plus `GREETING`,
publication, service-account creation, the environment-scoped `read` grant,
credential minting, machine delivery, render, embedded-newline refusal,
Docker Compose startup, container byte assertions, the doctor allowlist,
publish-to-sync stamp movement, and the restarted-container assertion.

Final printed assertion lines:

```text
compose demo passed: 21 stored values including GREETING delivered byte-exactly; surrounding whitespace proved trim-only transformation
compose demo passed: embedded newline refused by name with exit 4 and no generation/stamp change
compose demo passed: doctor returned only allowed findings; sync moved the stamp and restarted app
```

Final run time: `real 95.08s` (`user 8.16s`, `sys 5.53s`).

## Validation

- `bash -n scripts/compose-demo.sh`
- `shellcheck scripts/compose-demo.sh`
- `./scripts/ci/check-required-jobs_test.sh`
- `./scripts/ci/classify-changed-paths_test.sh`
- `git diff --check`

No other model or model CLI subprocess was invoked.
