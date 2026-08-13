-- SCIM provisioning (#73). Tenant-scoped statements: the reserved chain_*
-- parameter is bound by the store's binding layer from the verified proof's
-- resolved chain, never from a caller argument. Every SCIM wire operation
-- authorizes `scim-provision(org)` first, so `org_id` here is always the org
-- that proof resolved.

-- name: CreateSCIMBinding :exec
INSERT INTO scim_bindings (
    id, org_id, provider_kind, provider_id, provider_slug, provider_issuer, subject_source,
    nameid_format, nameid_qualifier, nameid_qualifier_present,
    nameid_sp_qualifier, nameid_sp_qualifier_present,
    connection_principal_id, created_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(provider_kind), sqlc.arg(provider_id), sqlc.arg(provider_slug),
    sqlc.arg(provider_issuer), sqlc.arg(subject_source), sqlc.arg(nameid_format),
    sqlc.arg(nameid_qualifier), sqlc.arg(nameid_qualifier_present),
    sqlc.arg(nameid_sp_qualifier), sqlc.arg(nameid_sp_qualifier_present),
    sqlc.arg(connection_principal_id), sqlc.arg(created_at)
);

-- name: GetSCIMBinding :one
SELECT id, org_id, provider_kind, provider_id, provider_slug, provider_issuer, subject_source,
       nameid_format, nameid_qualifier, nameid_qualifier_present,
       nameid_sp_qualifier, nameid_sp_qualifier_present,
       connection_principal_id, last_contact_at, created_at
FROM scim_bindings WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- name: ListSCIMBindings :many
SELECT id, org_id, provider_kind, provider_id, provider_slug, provider_issuer, subject_source,
       nameid_format, nameid_qualifier, nameid_qualifier_present,
       nameid_sp_qualifier, nameid_sp_qualifier_present,
       connection_principal_id, last_contact_at, created_at
FROM scim_bindings WHERE org_id = sqlc.arg(chain_org_id) ORDER BY id;

-- Push-only staleness bookkeeping (ADR section 9): the binding records
-- last-contact, and the surface reports it. Nothing self-heals from it.
-- name: TouchSCIMBinding :execrows
UPDATE scim_bindings SET last_contact_at = sqlc.arg(last_contact_at)
WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- name: DeleteSCIMBinding :execrows
DELETE FROM scim_bindings WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- name: CreateSCIMMapping :exec
INSERT INTO scim_mappings (
    id, org_id, binding_id, group_id, template, scope_project_id, scope_env_id,
    inert, created_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(binding_id), sqlc.arg(group_id),
    sqlc.arg(template), sqlc.arg(scope_project_id), sqlc.arg(scope_env_id),
    sqlc.arg(inert), sqlc.arg(created_at)
);

-- name: GetSCIMMapping :one
SELECT id, org_id, binding_id, group_id, template, scope_project_id, scope_env_id,
       inert, created_at
FROM scim_mappings WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- name: ListSCIMMappings :many
SELECT id, org_id, binding_id, group_id, template, scope_project_id, scope_env_id,
       inert, created_at
FROM scim_mappings
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY group_id, template, id;

-- name: ListSCIMMappingsForGroup :many
SELECT id, org_id, binding_id, group_id, template, scope_project_id, scope_env_id,
       inert, created_at
FROM scim_mappings
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND group_id = sqlc.arg(group_id)
ORDER BY template, id;

-- A mapping row whose group was deleted flips to inert (ADR section 5.4) and
-- raises an attention state; the human edits or deletes it. It is never
-- silently removed.
-- name: SetSCIMMappingInert :execrows
UPDATE scim_mappings SET inert = sqlc.arg(inert)
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND group_id = sqlc.arg(group_id);

-- name: DeleteSCIMMapping :execrows
DELETE FROM scim_mappings WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- name: DeleteSCIMMappingsForBinding :execrows
DELETE FROM scim_mappings
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: CreateSCIMUser :exec
INSERT INTO scim_users (
    id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
    subject, active, attributes, created_at, updated_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(binding_id), sqlc.arg(account_id),
    sqlc.arg(user_name), sqlc.arg(user_name_lower), sqlc.arg(external_id),
    sqlc.arg(subject), sqlc.arg(active), sqlc.arg(attributes),
    sqlc.arg(created_at), sqlc.arg(updated_at)
);

-- name: GetSCIMUser :one
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- The RFC 7643 caseExact:false lookup: userName compares case-insensitively,
-- which is why the folded column exists rather than a LOWER() in the predicate.
-- name: GetSCIMUserByUserName :one
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND user_name_lower = sqlc.arg(user_name_lower);

-- externalId compares BYTE-EXACT (ADR section 8). It is NOT unique -- only the
-- SUBJECT is -- so this returns MANY: an empty externalId is the default and a
-- singular query would answer an arbitrary one of them with totalResults 1.
-- name: ListSCIMUsersByExternalID :many
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND external_id = sqlc.arg(external_id)
ORDER BY id;

-- name: GetSCIMUserBySubject :one
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND subject = sqlc.arg(subject);

-- name: GetSCIMUserByAccount :one
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND account_id = sqlc.arg(account_id);

-- name: ListSCIMUsers :many
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY id;

-- name: UpdateSCIMUser :execrows
UPDATE scim_users
SET user_name = sqlc.arg(user_name), user_name_lower = sqlc.arg(user_name_lower),
    external_id = sqlc.arg(external_id), active = sqlc.arg(active),
    attributes = sqlc.arg(attributes), updated_at = sqlc.arg(updated_at)
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- name: DeleteSCIMUser :execrows
DELETE FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- name: DeleteSCIMUsersForBinding :execrows
DELETE FROM scim_users
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: CreateSCIMGroup :exec
INSERT INTO scim_groups (
    id, org_id, binding_id, display_name, display_name_lower, external_id,
    created_at, updated_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(binding_id),
    sqlc.arg(display_name), sqlc.arg(display_name_lower), sqlc.arg(external_id),
    sqlc.arg(created_at), sqlc.arg(updated_at)
);

-- name: GetSCIMGroup :one
SELECT id, org_id, binding_id, display_name, display_name_lower, external_id,
       created_at, updated_at
FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- Okta and Entra both discover a group by `displayName eq` before creating or
-- updating it; displayName is caseExact:false like userName. It is NOT unique
-- (RFC 7643 does not make it so), which is why this returns MANY: a directory
-- with two same-named groups must answer with two.
-- name: ListSCIMGroupsByDisplayName :many
SELECT id, org_id, binding_id, display_name, display_name_lower, external_id,
       created_at, updated_at
FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND display_name_lower = sqlc.arg(display_name_lower)
ORDER BY id;

-- externalId is not unique on groups either.
-- name: ListSCIMGroupsByExternalID :many
SELECT id, org_id, binding_id, display_name, display_name_lower, external_id,
       created_at, updated_at
FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND external_id = sqlc.arg(external_id)
ORDER BY id;

-- name: ListSCIMGroups :many
SELECT id, org_id, binding_id, display_name, display_name_lower, external_id,
       created_at, updated_at
FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY id;

-- name: UpdateSCIMGroup :execrows
UPDATE scim_groups
SET display_name = sqlc.arg(display_name), display_name_lower = sqlc.arg(display_name_lower),
    external_id = sqlc.arg(external_id), updated_at = sqlc.arg(updated_at)
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- name: DeleteSCIMGroup :execrows
DELETE FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND id = sqlc.arg(id);

-- name: DeleteSCIMGroupsForBinding :execrows
DELETE FROM scim_groups
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: AddSCIMGroupMember :exec
INSERT INTO scim_group_members (id, org_id, binding_id, group_id, user_id, created_at)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(binding_id),
    sqlc.arg(group_id), sqlc.arg(user_id), sqlc.arg(created_at)
);

-- name: ListSCIMGroupMembers :many
SELECT id, org_id, binding_id, group_id, user_id, created_at
FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND group_id = sqlc.arg(group_id)
ORDER BY user_id;

-- Which groups a user belongs to: the `groups` attribute is response-only per
-- RFC 7643, and this is the read that fills it.
-- name: ListSCIMGroupMembershipsForUser :many
SELECT id, org_id, binding_id, group_id, user_id, created_at
FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND user_id = sqlc.arg(user_id)
ORDER BY group_id;

-- name: DeleteSCIMGroupMember :execrows
DELETE FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id);

-- name: ClearSCIMGroupMembers :execrows
DELETE FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND group_id = sqlc.arg(group_id);

-- DELETE removes every member reference to the user IN THE SAME TRANSACTION
-- (ADR section 5.3), so a stale reference cannot exist after it.
-- name: DeleteSCIMGroupMembershipsForUser :execrows
DELETE FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND user_id = sqlc.arg(user_id);

-- name: DeleteSCIMGroupMembersForBinding :execrows
DELETE FROM scim_group_members
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: EnterSCIMAttention :exec
INSERT INTO scim_attention (id, org_id, binding_id, state, subject_ref, cause, entered_at)
VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(binding_id), sqlc.arg(state),
    sqlc.arg(subject_ref), sqlc.arg(cause), sqlc.arg(entered_at)
);

-- name: ListSCIMAttention :many
SELECT id, org_id, binding_id, state, subject_ref, cause, entered_at
FROM scim_attention
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY state, subject_ref;

-- name: ClearSCIMAttention :execrows
DELETE FROM scim_attention
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
  AND state = sqlc.arg(state) AND subject_ref = sqlc.arg(subject_ref);

-- name: DeleteSCIMAttentionForBinding :execrows
DELETE FROM scim_attention
WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- Narrowing a mapping row keeps its ID: origins key on it, so a delete-and-
-- recreate would release every origin the row holds and immediately recreate
-- most of them -- momentarily revoking capabilities that never stopped being
-- granted, and logging the holders out for a bookkeeping change.
-- name: UpdateSCIMMappingTemplate :execrows
UPDATE scim_mappings SET template = sqlc.arg(template)
WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- Every mutation on a binding's subtree takes this lock FIRST. It is a no-op
-- write, not a read: a SELECT takes no row lock, so two reconciliations for one
-- binding would interleave. `last_contact_at` is deliberately untouched -- an
-- administrator editing the mapping table is not the identity provider making
-- contact (ADR section 9).
-- name: LockSCIMBinding :execrows
UPDATE scim_bindings SET last_contact_at = last_contact_at
WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(id);

-- The WIRE's paged reads. Paging in Go over an unbounded read lets a valid
-- credential force full-directory work for a 200-item answer, every request;
-- LIMIT/OFFSET keeps the cost proportional to the page and the count query
-- keeps `totalResults` truthful (ADR section 8's ListResponse fields).
-- name: CountSCIMUsers :one
SELECT COUNT(*) FROM scim_users WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: PageSCIMUsers :many
SELECT id, org_id, binding_id, account_id, user_name, user_name_lower, external_id,
       subject, active, attributes, created_at, updated_at
FROM scim_users WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountSCIMGroups :one
SELECT COUNT(*) FROM scim_groups WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id);

-- name: PageSCIMGroups :many
SELECT id, org_id, binding_id, display_name, display_name_lower, external_id,
       created_at, updated_at
FROM scim_groups WHERE org_id = sqlc.arg(chain_org_id) AND binding_id = sqlc.arg(binding_id)
ORDER BY id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- Step (3) of the binding-deletion state machine. It runs AFTER the binding row
-- is gone -- scim_bindings.connection_principal_id references this row, so the
-- reverse order is a foreign-key violation -- which is why the scoping is
-- expressed as ORPHANHOOD rather than as a join onto a row that no longer
-- exists: the statement can only remove a provisioning connection that NO
-- binding still owns. Combined with an id read from the caller's own
-- proof-scoped binding row, a caller cannot name another org's live connection:
-- a live one is referenced and therefore unmatched, and an unreferenced one is
-- already ownerless. The kind and class predicates keep the statement incapable
-- of touching a human principal.
-- name: RetireSCIMConnectionPrincipal :execrows
DELETE FROM principals
WHERE principals.id = $1
  AND principals.kind = 'machine'
  AND principals.class = 'provisioning-connection'
  AND NOT EXISTS (
    SELECT 1 FROM scim_bindings AS b WHERE b.connection_principal_id = principals.id
  );
