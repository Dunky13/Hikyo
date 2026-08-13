-- +goose Up
-- Restore reconciliation (#76, ops spec § 11, threat model § Compromise
-- assumptions). Roll-forward only: no Down section by policy.
--
-- No new table. The restore checklist's two outstanding mechanisms are two
-- columns, because both are properties of state that already exists:
--
--   * `restore_epoch` marks the credential epoch a RESTORE produced, as
--     distinct from `credential_epoch`, which any epoch bump advances. The
--     two are separate facts and folding them would lose the one the grant
--     gate needs: "grants are inert until an operator commits the reconciled
--     set" has to know which epoch was reached by restoring, not merely that
--     the epoch moved. Zero means this instance has never been restored, so
--     every principal's default reconciliation state (also zero) already
--     satisfies the gate — a fresh instance is not born locked out.
--
--   * `reactivated_at` is the instant the restored instance came back. It is
--     the anchor for the federated-token skew predicate the machine-identity
--     ADR fixes (`iat > reactivated_at + 60 s`): a token minted before the
--     restore must not be presentable after it. NULL until a restore happens,
--     because "reactivated at the epoch" would be a claim about an act that
--     never occurred.
ALTER TABLE auth_instance_state ADD COLUMN restore_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_instance_state ADD COLUMN reactivated_at TIMESTAMPTZ;

-- The per-principal half of the same fact. A restore advances the instance's
-- restore epoch; a principal is inert for AUTHORIZATION until an operator
-- reconciles it up to that epoch, one principal at a time, under local host
-- authority. The grants themselves are untouched — the operator has to be
-- able to SEE what they are reconciling — they simply do not authorize.
--
-- It lives on the principal, not on the grant, for the reason the session
-- generation does: reconciliation is a statement about an identity ("this
-- principal is still who we think it is"), not about one capability line, and
-- a per-grant column would make it possible to reconcile half of somebody.
ALTER TABLE principals ADD COLUMN reconciled_epoch BIGINT NOT NULL DEFAULT 0;
