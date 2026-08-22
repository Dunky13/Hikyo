import {
  applyEnvTemplateOp,
  applyInstanceTemplateOp,
  applyOrgTemplateOp,
  applyProjectTemplateOp,
  createEnvGrantOp,
  createInstanceGrantOp,
  createOrgGrantOp,
  createProjectGrantOp,
  listInstanceGrantsOp,
  listOrgGrantsOp,
  revokeEnvGrantOp,
  revokeInstanceGrantOp,
  revokeOrgGrantOp,
  revokeProjectGrantOp,
} from '@hikyo/operations';
import type { GrantResult } from '@hikyo/client';
import { zGrantList } from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { useAuth } from '../app/AuthProvider.tsx';
import { ApiError, ok, parsed } from './client.ts';
import type { Grant } from './identities.ts';

/**
 * The membership surface, as the SPA sees it (#55, #60; locked prototype
 * app-chrome iteration 15).
 *
 * Four rules the permission ADR puts HERE rather than in a component, because
 * a component that got them wrong would be wrong quietly:
 *
 *  1. **The grant's scope IS the address, never a body member.** #55 refused a
 *     body-supplied scope for a reason that survives into the client: one
 *     operation per depth, chosen by the scope the human picked, so a caller
 *     authorized at one depth cannot write at another by editing a field.
 *     `createGrant` therefore dispatches on the scope's kind; there is no
 *     single "create" call to get wrong.
 *  2. **A capability may only be granted at or above its DEEPEST level.**
 *     `manage-projects` on one environment is a row nothing can evaluate, so
 *     the checklist offers, per scope, exactly the atoms that scope admits —
 *     the same table `internal/domain`'s `capabilityLevels` holds, transcribed
 *     with the ADR's own "Covers" wording as the explanation each `(?)` shows.
 *  3. **Each checked capability becomes its own revocable line.** The modal
 *     posts one create per capability. That is what a role template does with
 *     a preset checklist, and it is why revoking a chip never drags a bundle.
 *  4. **An org-scoped grant reaches every project and environment, current and
 *     future.** The ADR binds the UI to make that visible AT GRANT TIME; the
 *     blast enumeration below is computed from the org's real topology, never
 *     summarised.
 */

// --- the closed atom table --------------------------------------------------

/**
 * Level is the scope depth a grant is written at. `instance` is present
 * because the instance-administration surface grants there; it is not offered
 * inside an organisation.
 */
export type Level = 'instance' | 'org' | 'project' | 'environment';

type CapabilityAtom = {
  readonly id: string;
  /** The DEEPEST scope the atom may be granted at (domain.capabilityLevels). */
  readonly deepest: Level;
  /** The permission ADR's own "Covers" wording, verbatim. */
  readonly covers: string;
};

type RegistryCapability = CapabilityAtom & { readonly humanGrantable: boolean };

/** Full domain registry, including atoms that org surfaces must not offer. */
const CAPABILITY_REGISTRY: readonly RegistryCapability[] = [
  {
    id: 'read',
    deepest: 'environment',
    covers:
      'the environment exists; the project key catalogue, descriptions, schemas, validation status, diffs (write-presence only for secret keys); config values',
    humanGrantable: true,
  },
  { id: 'reveal', deepest: 'environment', covers: 'current secret plaintext, by any route', humanGrantable: true },
  {
    id: 'reveal-history',
    deepest: 'environment',
    covers: 'superseded secret plaintext, by any route',
    humanGrantable: true,
  },
  {
    id: 'edit',
    deepest: 'environment',
    covers: "change values in the principal's own working state; creates no revision",
    humanGrantable: true,
  },
  {
    id: 'publish',
    deepest: 'environment',
    covers: 'commit a revision — including rollback, apply, and any publish whose effect reaches this environment',
    humanGrantable: true,
  },
  { id: 'pin', deepest: 'environment', covers: 'create, reassign or release a revision pin for this environment', humanGrantable: true },
  {
    id: 'audit-read',
    deepest: 'environment',
    covers: 'read the audit trail for this scope: its own power, and a second factor is required',
    humanGrantable: true,
  },
  {
    id: 'definitions-edit',
    deepest: 'project',
    covers: 'the definitions bundle: keys, rules, folder paths, and environment topology (create/delete environments)',
    humanGrantable: true,
  },
  {
    id: 'project-settings',
    deepest: 'project',
    covers: 'protected-environment flag, definitions_source, reauthentication window, retention policy',
    humanGrantable: true,
  },
  { id: 'manage-identities', deepest: 'project', covers: 'service accounts and their scoped credentials', humanGrantable: true },
  { id: 'manage-adapters', deepest: 'project', covers: 'deployment-module configuration and sync triggering', humanGrantable: true },
  { id: 'manage-members', deepest: 'project', covers: 'create, modify and revoke grants at or below that scope', humanGrantable: true },
  { id: 'manage-projects', deepest: 'org', covers: 'create and delete projects', humanGrantable: true },
  {
    id: 'credential-reset',
    deepest: 'org',
    covers: 'issue a credential-establishment authority for another account in this organisation',
    humanGrantable: true,
  },
  { id: 'backup-export', deepest: 'instance', covers: 'produce an age-encrypted backup container; never a plaintext values export', humanGrantable: true },
  { id: 'restore', deepest: 'instance', covers: 'restore the instance from an encrypted backup container', humanGrantable: true },
  { id: 'rotate-root-key', deepest: 'instance', covers: 'rotate the instance root encryption key', humanGrantable: true },
  { id: 'rotate-master-key', deepest: 'instance', covers: 'rotate the instance master encryption key', humanGrantable: true },
  { id: 'rotate-dek', deepest: 'instance', covers: 'rotate project data-encryption keys', humanGrantable: true },
  { id: 'reencrypt', deepest: 'instance', covers: 're-encrypt stored material under the current key hierarchy', humanGrantable: true },
  { id: 'instance-config', deepest: 'instance', covers: 'administer instance-wide configuration and organisations', humanGrantable: true },
  { id: 'instance-directory', deepest: 'instance', covers: "read the directory of connected instances and serve this instance's listing", humanGrantable: true },
  {
    id: 'scim-provision',
    deepest: 'org',
    covers: 'operate one SCIM provisioning connection',
    humanGrantable: false,
  },
];

/**
 * TENANT_CAPABILITIES is every atom grantable INSIDE an organisation.
 *
 * Instance-only atoms are deliberately absent from this tenant subset because
 * offering them on an org surface would offer a refusal. `scim-provision` is
 * absent for a different reason — it is system-created with its SCIM binding
 * and refused BY NAME through the grant API (#73).
 */
export const TENANT_CAPABILITIES: readonly CapabilityAtom[] = CAPABILITY_REGISTRY.filter(
  (atom) => atom.deepest !== 'instance' && atom.humanGrantable,
);

const DEPTH: Record<Level, number> = { instance: 0, org: 1, project: 2, environment: 3 };

/**
 * capabilitiesAt returns the atoms a scope of this level admits.
 *
 * A grant is legal at its atom's deepest level or ANY level above it, because
 * grants inherit downward — so an org scope admits everything and an
 * environment scope admits only the environment atoms. Instance scope admits
 * both the tenant atoms (by downward inheritance) and the instance-only atoms.
 */
export function capabilitiesAt(level: Level): readonly CapabilityAtom[] {
  if (level === 'instance') {
    return CAPABILITY_REGISTRY.filter(
      (atom) => atom.humanGrantable && DEPTH[level] <= DEPTH[atom.deepest],
    );
  }
  return TENANT_CAPABILITIES.filter((atom) => DEPTH[level] <= DEPTH[atom.deepest]);
}

/** RoleTemplate is the closed v1 set, with the levels its ADR row admits. */
const ROLE_TEMPLATE_IDS = [
  'viewer',
  'editor',
  'publisher',
  'revealer',
  'historian',
  'maintainer',
  'admin',
  'operator',
] as const;

type RoleTemplate = {
  readonly id: (typeof ROLE_TEMPLATE_IDS)[number];
  readonly levels: readonly Level[];
  readonly seeds: readonly string[];
  readonly orgOnly: readonly string[];
};

/**
 * ROLE_TEMPLATES is the shortcut, not a stored thing: applying one expands AT
 * GRANT TIME into independent grants. Level filtering keeps `operator` on the
 * instance surface and every tenant template off it.
 */
export const ROLE_TEMPLATES: readonly RoleTemplate[] = [
  { id: 'viewer', levels: ['org', 'project', 'environment'], seeds: ['read'], orgOnly: [] },
  { id: 'editor', levels: ['org', 'project', 'environment'], seeds: ['read', 'edit'], orgOnly: [] },
  {
    id: 'publisher',
    levels: ['org', 'project', 'environment'],
    seeds: ['read', 'edit', 'publish', 'pin'],
    orgOnly: [],
  },
  { id: 'revealer', levels: ['org', 'project', 'environment'], seeds: ['reveal'], orgOnly: [] },
  { id: 'historian', levels: ['org', 'project', 'environment'], seeds: ['reveal-history'], orgOnly: [] },
  {
    id: 'maintainer',
    levels: ['org', 'project'],
    seeds: ['read', 'edit', 'publish', 'pin', 'definitions-edit', 'manage-identities', 'manage-adapters'],
    orgOnly: [],
  },
  {
    id: 'admin',
    levels: ['org', 'project'],
    seeds: ['read', 'edit', 'publish', 'pin', 'definitions-edit', 'manage-identities', 'manage-adapters', 'project-settings', 'manage-members', 'reveal', 'reveal-history'],
    orgOnly: ['manage-projects'],
  },
  { id: 'operator', levels: ['instance'], seeds: ['backup-export', 'restore', 'rotate-root-key', 'rotate-master-key', 'rotate-dek', 'reencrypt', 'instance-config', 'manage-members'], orgOnly: [] },
];

export function templatesAt(level: Level): readonly RoleTemplate[] {
  return ROLE_TEMPLATES.filter((template) => template.levels.includes(level));
}

export function expandTemplate(templateId: RoleTemplate['id'], level: Level): readonly string[] {
  const template = ROLE_TEMPLATES.find((candidate) => candidate.id === templateId);
  if (template === undefined || !template.levels.includes(level)) {
    throw new Error(`role template ${templateId} is not admitted at ${level} scope`);
  }
  return level === 'org' ? [...template.seeds, ...template.orgOnly] : template.seeds;
}

// --- scopes -----------------------------------------------------------------

export type ScopeRef =
  | { readonly kind: 'instance' }
  | { readonly kind: 'org'; readonly org: string }
  | { readonly kind: 'project'; readonly org: string; readonly project: string }
  | {
      readonly kind: 'environment';
      readonly org: string;
      readonly project: string;
      readonly environment: string;
    };

export type ScopeOption = {
  /** The select's value: an opaque, parseable address. */
  readonly value: string;
  readonly label: string;
  readonly scope: ScopeRef;
  readonly level: Level;
  /** The project this option groups under; the org option groups alone. */
  readonly group: string;
  /**
   * Protection as the environment's own settings report it. `null` means the
   * caller could not read them — which is a real state (a member manager needs
   * no `read`), and one that must never be presented as "not protected".
   */
  readonly isProtected: boolean | null;
};

export type EnvironmentNode = {
  readonly id: string;
  readonly name: string;
  readonly isProtected: boolean | null;
};

export type ProjectNode = {
  readonly id: string;
  readonly name: string;
  readonly environments: readonly EnvironmentNode[];
};

export function scopeValue(scope: ScopeRef): string {
  switch (scope.kind) {
    case 'instance':
      return 'instance';
    case 'org':
      return `org:${scope.org}`;
    case 'project':
      return `project:${scope.project}`;
    case 'environment':
      return `env:${scope.project}:${scope.environment}`;
  }
}

/**
 * scopeOptions orders the grant modal's scope select NARROW TO WIDE, with
 * every known-protected environment last inside its project.
 *
 * The order is the argument: a select whose first entry is the widest scope
 * makes the widest grant the cheapest gesture, and the ADR's own honest
 * consequence — an org-scoped `reveal` reveals in production — is exactly the
 * mistake a careless default produces.
 */
export function scopeOptions(org: string, orgName: string, projects: readonly ProjectNode[]): ScopeOption[] {
  const options: ScopeOption[] = [];
  for (const project of projects) {
    const ordered = [
      ...project.environments.filter((env) => env.isProtected !== true),
      ...project.environments.filter((env) => env.isProtected === true),
    ];
    for (const env of ordered) {
      const scope: ScopeRef = {
        kind: 'environment',
        org,
        project: project.id,
        environment: env.id,
      };
      options.push({
        value: scopeValue(scope),
        label:
          env.isProtected === true
            ? `${env.name} (protected)`
            : env.isProtected === null
              ? `${env.name} (protection unreadable)`
              : env.name,
        scope,
        level: 'environment',
        group: `${project.name} · environments`,
        isProtected: env.isProtected,
      });
    }
  }
  for (const project of projects) {
    const scope: ScopeRef = { kind: 'project', org, project: project.id };
    options.push({
      value: scopeValue(scope),
      label: `${project.name} (every environment)`,
      scope,
      level: 'project',
      group: 'Projects',
      isProtected: null,
    });
  }
  const orgScope: ScopeRef = { kind: 'org', org };
  options.push({
    value: scopeValue(orgScope),
    label: `${orgName} (every project and environment)`,
    scope: orgScope,
    level: 'org',
    group: 'Organisation',
    isProtected: null,
  });
  return options;
}

/**
 * defaultScopeValue is the SAFEST preselection, and it is empty when there is
 * no safe one.
 *
 * The rule: prefer an environment named staging whose settings explicitly say
 * it is NOT protected, then the first other confirmed-unprotected environment.
 * A protected environment is never preselected, and neither is one whose protection could not be read:
 * "unknown" preselected as "fine" is how a careless default becomes a
 * production disclosure. When nothing qualifies the human chooses explicitly,
 * which is the honest fallback rather than a silently wide default.
 */
export function defaultScopeValue(options: readonly ScopeOption[]): string {
  const safe = options.filter(
    (option) => option.level === 'environment' && option.isProtected === false,
  );
  const staging = safe.find((option) => option.label.toLocaleLowerCase() === 'staging');
  if (staging !== undefined) {
    return staging.value;
  }
  const first = safe[0];
  return first === undefined ? '' : first.value;
}

export function optionByValue(
  options: readonly ScopeOption[],
  value: string,
): ScopeOption | undefined {
  return options.find((option) => option.value === value);
}

// --- membership -------------------------------------------------------------

type MembershipRow = {
  readonly key: string;
  readonly principal: string;
  readonly scopeLabel: string;
  readonly level: Level;
  readonly grants: readonly Grant[];
};

export function scopeOf(grant: Grant): ScopeRef {
  const { org_id: org, project_id: project, environment_id: environment } = grant.scope;
  if (environment !== undefined) {
    if (org === undefined || project === undefined) {
      throw new Error(`grant ${grant.id} has an environment without its project and organisation`);
    }
    return { kind: 'environment', org, project, environment };
  }
  if (project !== undefined) {
    if (org === undefined) {
      throw new Error(`grant ${grant.id} has a project without its organisation`);
    }
    return { kind: 'project', org, project };
  }
  if (org !== undefined) {
    return { kind: 'org', org };
  }
  return { kind: 'instance' };
}

function grantScopeLevel(grant: Grant): Level {
  return scopeOf(grant).kind;
}

/** Names is how a row turns opaque ids into the words on the page. */
export type Names = {
  readonly org: (id: string) => string;
  readonly project: (id: string) => string;
  readonly environment: (id: string) => string;
};

export function grantScopeLabel(grant: Grant, names: Names): string {
  const scope = scopeOf(grant);
  switch (scope.kind) {
    case 'environment':
      return `${names.project(scope.project)} · ${names.environment(scope.environment)}`;
    case 'project':
      return `${names.project(scope.project)} · every environment`;
    case 'org':
      return `${names.org(scope.org)} · every project`;
    case 'instance':
      return 'instance · everything';
  }
}

export function revokeOutcomeText(grant: Grant, survivor: Grant | undefined, names: Names): string {
  if (survivor === undefined) {
    return `Revoked ${grant.capability} on ${grantScopeLabel(grant, names)} for ${grant.principal_id}. The grant row is gone, and sessions carrying that authority are gone.`;
  }
  const origins = survivor.origins
    .map((origin) => `${origin.kind}: ${origin.subject}`)
    .join(', ');
  return `Released the revocable origin for ${grant.capability} on ${grantScopeLabel(grant, names)}. The grant remains effective through ${origins}; those origins still authorise it.`;
}

/**
 * membershipRows groups the grant lines one row per (principal, scope), which
 * is the shape the prototype's table has and the shape the question has: "what
 * does this person hold HERE". Each capability inside the row stays its own
 * line with its own origins and its own revoke.
 */
export function membershipRows(grants: readonly Grant[], names: Names): MembershipRow[] {
  const rows = new Map<string, MembershipRow & { grants: Grant[] }>();
  for (const grant of grants) {
    const level = grantScopeLevel(grant);
    const key = `${grant.principal_id}|${scopeKeyOf(grant)}`;
    const row = rows.get(key);
    if (row === undefined) {
      rows.set(key, {
        key,
        principal: grant.principal_id,
        scopeLabel: grantScopeLabel(grant, names),
        level,
        grants: [grant],
      });
      continue;
    }
    row.grants.push(grant);
  }
  return [...rows.values()].map((row) => ({
    ...row,
    grants: [...row.grants].sort((a, b) => a.capability.localeCompare(b.capability)),
  }));
}

function scopeKeyOf(grant: Grant): string {
  return scopeValue(scopeOf(grant));
}

/**
 * covers answers whether a grant line reaches a target scope, which is the
 * "who can…?" inspection's whole computation. It is the downward inheritance
 * rule and nothing else: a grant at a scope applies to that scope and
 * everything beneath it.
 */
export function covers(grant: Grant, target: ScopeRef): boolean {
  const scope = scopeOf(grant);
  if (scope.kind === 'instance') {
    return true;
  }
  if (target.kind === 'instance' || scope.org !== target.org) {
    return false;
  }
  if (scope.kind === 'org') {
    return true;
  }
  if (target.kind === 'org' || scope.project !== target.project) {
    return false;
  }
  if (scope.kind === 'project') {
    return true;
  }
  return target.kind === 'environment' && scope.environment === target.environment;
}

/** whoCan is the inspection answer: every line of `capability` reaching `target`. */
export function whoCan(
  grants: readonly Grant[],
  capability: string,
  target: ScopeRef,
): readonly Grant[] {
  return grants.filter((grant) => grant.capability === capability && covers(grant, target));
}

// --- blast radius -----------------------------------------------------------

type BlastLine = { readonly project: string; readonly environments: string };

/**
 * blastRadius enumerates what an ORG-scoped grant reaches: every project and
 * every environment in the organisation, plus the line the enumeration cannot
 * show — the projects that do not exist yet and inherit anyway.
 *
 * Enumerated rather than summarised on purpose. "All projects" is a phrase a
 * human skims; a list with production in it is one they read.
 */
export function blastRadius(projects: readonly ProjectNode[]): BlastLine[] {
  const lines = projects.map((project) => ({
    project: project.name,
    environments:
      project.environments.length === 0
        ? 'no environments yet'
        : project.environments
            .map((env) =>
              env.isProtected === true
                ? `${env.name} (protected)`
                : env.isProtected === null
                  ? `${env.name} (protection unreadable)`
                  : env.name,
            )
            .join(' · '),
  }));
  lines.push({
    project: 'any project created later',
    environments: 'inherits automatically, with no further decision',
  });
  return lines;
}

// --- queries and mutations --------------------------------------------------

type GrantList = z.infer<typeof zGrantList>;

const orgGrantsKey = (org: string) => ['org-grants', org] as const;
const instanceGrantsKey = ['instance-grants'] as const;

/**
 * useOrgGrants is the membership listing.
 *
 * `listOrgGrants` answers org, project AND environment scoped lines in one
 * read — which is why this surface needs no second listing per depth, and why
 * there is no `grant.list-env` to call: "who can reach this environment" has
 * to include the lines above it, and an environment-only listing would omit
 * exactly those.
 */
export function useOrgGrants(org: string): UseQueryResult<GrantList> {
  return useQuery({
    queryKey: orgGrantsKey(org),
    queryFn: () => parsed(listOrgGrantsOp, { path: { org } }),
    enabled: org !== '',
    retry: false,
  });
}

export function useInstanceGrants(): UseQueryResult<GrantList> {
  return useQuery({
    queryKey: instanceGrantsKey,
    queryFn: () => parsed(listInstanceGrantsOp, {}),
    retry: false,
  });
}

type GrantInput = { readonly principal: string; readonly capability: string };
type GrantOutcomeView = Pick<GrantResult, 'capability' | 'outcome'>;

function createOne(scope: ScopeRef, input: GrantInput) {
  const body = { principal: input.principal, capability: input.capability };
  switch (scope.kind) {
    case 'instance':
      return parsed(createInstanceGrantOp, { body });
    case 'environment':
      return parsed(createEnvGrantOp, {
          path: { org: scope.org, project: scope.project, environment: scope.environment },
          body,
        });
    case 'project':
      return parsed(createProjectGrantOp, { path: { org: scope.org, project: scope.project }, body });
    case 'org':
      return parsed(createOrgGrantOp, { path: { org: scope.org }, body });
  }
}

export class GrantPartialFailure extends Error {
  override readonly cause: unknown;

  constructor(
    readonly completed: readonly GrantOutcomeView[],
    readonly failedCapability: string,
    readonly total: number,
    cause: unknown,
  ) {
    super(`granting ${failedCapability} failed after ${completed.length} earlier capabilities`, { cause });
    this.name = 'GrantPartialFailure';
    this.cause = cause;
  }
}

export async function createGrantsSequentially<Result extends GrantOutcomeView>(
  capabilities: readonly string[],
  create: (capability: string) => Promise<Result>,
): Promise<readonly Result[]> {
  const results: Result[] = [];
  for (const capability of capabilities) {
    try {
      results.push(await create(capability));
    } catch (error) {
      throw new GrantPartialFailure(results, capability, capabilities.length, error);
    }
  }
  return results;
}

export function grantOutcomeSummary(results: readonly GrantOutcomeView[]): string {
  const created: string[] = [];
  const originAdded: string[] = [];
  const unchanged: string[] = [];
  for (const result of results) {
    switch (result.outcome) {
      case 'created':
        created.push(result.capability);
        break;
      case 'origin_added':
        originAdded.push(result.capability);
        break;
      case 'unchanged':
        unchanged.push(result.capability);
        break;
      default: {
        const impossible: never = result.outcome;
        return impossible;
      }
    }
  }
  const render = (items: readonly string[]) => (items.length === 0 ? 'none' : items.join(', '));
  return `Created: ${render(created)}. Origin added: ${render(originAdded)}. Unchanged: ${render(unchanged)}.`;
}

/**
 * useCreateGrants posts ONE create per checked capability, in order, and stops
 * at the first refusal.
 *
 * Sequential rather than concurrent, and it matters: each create advances the
 * target principal's session generation inside its own transaction, and the
 * writers serialize on that principal's row anyway. Stopping at the first
 * refusal reports how far it got, which is the same honest partial-failure
 * shape #55 gave `access member remove`.
 */
export function useCreateGrants() {
  const auth = useAuth();
  return useMutation({
    mutationFn: async (input: {
      scope: ScopeRef;
      principal: string;
      capabilities: readonly string[];
    }) => {
      return createGrantsSequentially(input.capabilities, (capability) =>
        createOne(input.scope, { principal: input.principal, capability }),
      );
    },
    onSettled: () => auth.refreshSession(),
  });
}

export function useApplyTemplate() {
  const auth = useAuth();
  return useMutation({
    mutationFn: (input: { scope: ScopeRef; principal: string; template: string }) => {
      const body = { principal: input.principal, template: templateOf(input.template) };
      switch (input.scope.kind) {
        case 'instance':
          return parsed(applyInstanceTemplateOp, { body });
        case 'environment':
          return parsed(applyEnvTemplateOp, {
              path: {
                org: input.scope.org,
                project: input.scope.project,
                environment: input.scope.environment,
              },
              body,
            });
        case 'project':
          return parsed(applyProjectTemplateOp, {
              path: { org: input.scope.org, project: input.scope.project },
              body,
            });
        case 'org':
          return parsed(applyOrgTemplateOp, { path: { org: input.scope.org }, body });
      }
    },
    onSettled: () => auth.refreshSession(),
  });
}

/**
 * templateOf narrows a select's string to the generated closed enum without a
 * cast: the generated request type names the eight, and an unknown one is a
 * bug in this file rather than something to send and let the server judge.
 */
function templateOf(
  value: string,
): RoleTemplate['id'] {
  for (const template of ROLE_TEMPLATES) {
    if (template.id === value) {
      return template.id;
    }
  }
  throw new Error(`unknown role template ${value}`);
}

export function useRevokeGrant() {
  const auth = useAuth();
  return useMutation({
    mutationFn: (input: { grant: Grant }) => {
      const query = {
        principal: input.grant.principal_id,
        capability: input.grant.capability,
      };
      const scope = scopeOf(input.grant);
      switch (scope.kind) {
        case 'environment':
          return ok(revokeEnvGrantOp, {
              path: { org: scope.org, project: scope.project, environment: scope.environment },
              query,
            });
        case 'project':
          return ok(revokeProjectGrantOp, { path: { org: scope.org, project: scope.project }, query });
        case 'org':
          return ok(revokeOrgGrantOp, { path: { org: scope.org }, query });
        case 'instance':
          return ok(revokeInstanceGrantOp, { query });
      }
    },
    onSettled: () => auth.refreshSession(),
  });
}

// --- refusals ---------------------------------------------------------------

/**
 * grantFailureText maps a refusal onto something true.
 *
 * The 403 line is not a guess: `manage-members` is MFA-mandatory, and
 * `isolation.TestTenantRoutesDeclareForbiddenOnlyForMFA` pins that a tenant
 * route declares 403 for that reason and no other — so on this surface a 403
 * IS the second-factor refusal. A 404 is the uniform nonexistent shape: it
 * cannot be distinguished from a genuine miss, and saying otherwise would
 * invent the oracle the server closed.
 */
export function grantFailureText(error: unknown): string {
  if (error instanceof GrantPartialFailure) {
    if (error.completed.length === 0) {
      return grantFailureText(error.cause);
    }
    return (
      `Completed ${String(error.completed.length)} of ${String(error.total)} (live and listed below). ` +
      `${grantOutcomeSummary(error.completed)} ` +
      `${error.failedCapability} was refused: ${grantFailureText(error.cause)}`
    );
  }
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return (
          error.detail ??
          'That grant was refused: the capability cannot be held at this scope, or this principal may not hold it.'
        );
      case 401:
        return 'Your session ended. Sign in again to continue.';
      case 403:
        return 'Managing members needs a second factor. Sign in again and present your passkey or a code, then retry.';
      case 404:
        return 'This scope is not available to you, or it does not exist. The two are deliberately the same answer.';
      case 409:
        return (
          error.detail ??
          'Refused: this would leave the organisation with nobody able to manage its members.'
        );
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `The server failed (${error.status}); whether the change applied is unknown — reload to check.`;
    }
  }
  return 'The grant surface could not be reached, or it answered something this client does not understand. Whether the change applied is unknown — reload to check.';
}

export function membershipFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 401:
        return 'Your session ended. Sign in again to read this membership listing.';
      case 403:
        return 'This membership listing needs a second factor. Sign in again and present your passkey or a code, then retry.';
      case 404:
        return 'This organisation does not exist, or it is not available to you. The two are deliberately the same answer.';
      case 429:
        return 'Too many membership reads right now. Wait a moment and reload.';
      default:
        return `The server failed while reading memberships (${error.status}). Reload to try again.`;
    }
  }
  return 'The membership listing could not be reached, or its response did not match the contract. Reload to try again.';
}
