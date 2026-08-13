-- +goose Up
-- The workspace session's assurance record (#71, multi-instance ADR).
-- Roll-forward only: no Down section by policy.
--
-- The ADR requires a workspace session to match the locked session model "in
-- every locked mechanical respect", and it names the assurance record in that
-- list. Before this migration the redemption minted the row with an EMPTY
-- factor list, which made every workspace session permanently single-factor:
-- the safe direction, but a wrong one — a human who authenticated to this
-- instance with a passkey in the popup got a session that claimed they had
-- not.
--
-- The factors belong to the session that APPROVED the handoff, and approval
-- and redemption are two separate requests minutes apart, so the transaction
-- row is the only place that fact can travel. Hence one column here rather
-- than a lookup at redeem: the approving session may have been revoked,
-- rotated or logged out between the two calls, and the assurance that matters
-- is the one the human actually demonstrated AT THE CEREMONY.
--
-- NOT NULL DEFAULT '[]' rather than nullable: an absent assurance record and
-- an empty one are the same thing to every consumer (`assuranceInadequate`
-- reads the list), and a nullable column would add a NULL branch to a JSON
-- decode for no fact it could carry.
--
-- No new table, so no `hikyo:table` directive: the columns inherit
-- `workspace_handoffs`' own class=authn annotation from 00019, which is
-- correct for them — the assurance record is resolved at authentication time
-- and cannot itself ride a proof.
ALTER TABLE workspace_handoffs ADD COLUMN factors TEXT NOT NULL DEFAULT '[]';

-- `factor_class` is the FRESH ceremony the approving human completed inside the
-- popup, as part of the approval, recorded separately from `factors` because
-- the two answer different questions: `factors` is the assurance record the
-- session carries, `factor_class` is what was demonstrated JUST NOW. An
-- elevation reads the second one, so a session that logged in with a passkey
-- days ago cannot elevate without touching an authenticator again.
ALTER TABLE workspace_handoffs ADD COLUMN factor_class TEXT NOT NULL DEFAULT '';

-- EVERY PRE-EXISTING APPROVED-BUT-UNREDEEMED HANDOFF IS INVALIDATED, rather
-- than back-filled with the '[]' / '' defaults above. A default is a claim, and
-- the claim it would make here is false twice over: that the approving human
-- demonstrated nothing (which under-assures the session about to be minted)
-- and that no fresh ceremony is required of it (which is precisely the gate
-- this migration exists to install). A rolling deployment makes it worse — an
-- old process can approve a NEW row without writing either column — so the
-- redeem path additionally refuses an approved step-up carrying no factor
-- class, and this DELETE only removes the rows that would otherwise sit in
-- that state at cutover. Handoffs live ten minutes; the cost of invalidation
-- is that a popup opened across the upgrade is reopened.
DELETE FROM workspace_handoffs;

-- The reauthentication window gains the EXACT BINDING a step-up consent
-- carries. Both default to the empty string, which means UNBOUND: every
-- existing opener (TOTP, OIDC, WebAuthn) writes no binding and keeps today's
-- environment-wide semantics, while a window opened by a workspace step-up
-- names the one operation and the one key set the human consented to. The
-- consumption gate refuses a bound window presented for anything else, so an
-- approval for `key.reveal` over DATABASE_URL cannot be spent on another
-- operation or another key.
--
-- `bound_key_set` is the canonical form the service computes: the key ids
-- sorted and newline-joined. Sorting at the boundary is what makes the
-- comparison a set comparison rather than an ordering accident.
ALTER TABLE reauth_windows ADD COLUMN bound_operation TEXT NOT NULL DEFAULT '';
ALTER TABLE reauth_windows ADD COLUMN bound_key_set TEXT NOT NULL DEFAULT '';
