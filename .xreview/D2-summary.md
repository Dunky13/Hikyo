# Stream D2 summary — Compose demo follow-up (#63)

## Fixed

- Replaced the unrelated instance grant set with the required
  `instance-config@instance` grant.
- Added the missing `manage-projects` capability to the org-scoped union and
  verified `project create` and `env create` now succeed.
- Corrected `values set` to address values by key name rather than key id,
  collected immutable publish version ids from each staging response, and made
  the string declaration explicitly accept the empty corpus value.
- Preserved the original Docker config while Hikyo uses an isolated temporary
  `HOME`, and exported the configured absolute `HIKYO_RUNTIME_DIR` for Compose.
- Added exact expected/observed base64 to container round-trip failures.

## Final demo status

Command:

```text
GOCACHE=/tmp/hikyo-go-build-cache ./scripts/compose-demo.sh
```

The final run reached hierarchy creation, 20 representable corpus keys plus
`GREETING`, publication, service-account creation, environment-scoped `read`
grant, credential minting, machine delivery, render, the embedded-newline
refusal check, Docker Compose startup, and container assertions. Fifteen corpus
values passed before `LEADING_SPACE` failed.

The blocking CLI command receives stdin containing the exact bytes
`"   value"`:

```text
hikyo values set LEADING_SPACE --context demo --org <org_id> \
  --project <project_id> --env <environment_id> --stdin -o json
```

It exits `0`. Stderr is the target line followed by:

```text
staged LEADING_SPACE (set); publish it with: hikyo values publish --versions <version_id>
```

After publish/render, the container assertion reports:

```text
compose demo: container did not round-trip LEADING_SPACE (want base64 ICAgdmFsdWU=, got dmFsdWU=)
```

`--value-file` produced the same result. An isolated run of the committed
Compose file with the same raw env-file bytes produced `ICAgdmFsdWU=`, so
Compose and the Alpine print command preserve the value; the public value-input
CLI path is the boundary that removes the leading bytes. Per the brief, no Go
code and no API/datastore bypass was added. Doctor, sync, and the script's three
terminal success assertion lines were not reached.

Final run time: `real 105.16s` (`user 7.92s`, `sys 6.10s`).

## Validation

Passed:

- `bash -n scripts/compose-demo.sh`
- `shellcheck scripts/compose-demo.sh`
- `./scripts/ci/check-required-jobs_test.sh`
- `./scripts/ci/classify-changed-paths_test.sh`
- `git diff --check`

No model or model CLI subprocess was invoked.
