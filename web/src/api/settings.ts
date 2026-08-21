import {
  createEnvironment,
  createOrg,
  createProject,
  deleteOrg,
  deleteProject,
  getEnvironmentSettings,
  getOrg,
  getOrgRetention,
  getProject,
  getProjectRetention,
  listEnvironments,
  listOrgs,
  listProjects,
  renameOrg,
  renameProject,
  rotateTokenKey,
  setEnvironmentSettings,
  setOrgRetention,
  setProjectRetention,
} from '@hikyo/client';
import {
  zEnvironment,
  zEnvironmentList,
  zEnvironmentSettings,
  zOrg,
  zOrgList,
  zProject,
  zProjectList,
  zProjectRetentionPolicy,
  zRetentionPolicy,
} from '@hikyo/zod';
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from '@tanstack/react-query';
import type { Client } from '@hikyo/runtime-core';
import type { z } from 'zod';

import { ApiError, ok, parsed } from './client.ts';
import type { EnvironmentNode, ProjectNode } from './access.ts';
import { useTransport } from './transport.tsx';

/**
 * The organisation, project and instance settings surfaces (#60), riding the
 * hierarchy and retention APIs (#48, #53) exactly as they are.
 *
 * Pure formatting and validation live here so both retention editors preserve
 * the wire's exact seconds and refuse malformed human input the same way.
 */

type Org = z.infer<typeof zOrg>;
type OrgList = z.infer<typeof zOrgList>;
type Project = z.infer<typeof zProject>;
export type RetentionPolicy = z.infer<typeof zRetentionPolicy>;
export type ProjectRetentionPolicy = z.infer<typeof zProjectRetentionPolicy>;
type EnvironmentSettings = z.infer<typeof zEnvironmentSettings>;

const orgKey = (org: string) => ['org', org] as const;
const orgsListKey = ['orgs-instance'] as const;
const projectsKey = (org: string) => ['projects', org] as const;
const projectKey = (org: string, project: string) => ['project', org, project] as const;
const environmentsKey = (org: string, project: string) =>
  ['environments', org, project] as const;
const environmentSettingsKey = (org: string, project: string, environment: string) =>
  ['environment-settings', org, project, environment] as const;
const orgRetentionKey = (org: string) => ['org-retention', org] as const;
const projectRetentionKey = (org: string, project: string) =>
  ['project-retention', org, project] as const;

// --- reads ------------------------------------------------------------------

export function useOrg(org: string): UseQueryResult<Org> {
  return useQuery({
    queryKey: orgKey(org),
    queryFn: () => parsed(getOrg({ path: { org } }), zOrg),
    enabled: org !== '',
    retry: false,
  });
}

export function useProject(org: string, project: string): UseQueryResult<Project> {
  return useQuery({
    queryKey: projectKey(org, project),
    queryFn: () => parsed(getProject({ path: { org, project } }), zProject),
    enabled: org !== '' && project !== '',
    retry: false,
  });
}

export function useEnvironments(
  org: string,
  project: string,
): UseQueryResult<z.infer<typeof zEnvironmentList>> {
  const transport = useTransport();
  return useQuery(environmentListQueryOptions(org, project, transport.client));
}

function environmentListQueryOptions(org: string, project: string, client?: Client) {
  return {
    queryKey: environmentsKey(org, project),
    queryFn: () => parsed(listEnvironments({ path: { org, project }, client }), zEnvironmentList),
    enabled: org !== '' && project !== '',
    retry: false,
  } as const;
}

/** One canonical project-list hook and query key for every chrome surface. */
export function useProjects(org: string): UseQueryResult<z.infer<typeof zProjectList>> {
  const transport = useTransport();
  return useQuery({
    queryKey: projectsKey(org),
    queryFn: () => parsed(listProjects({ path: { org }, ...transport }), zProjectList),
    enabled: org !== '',
    retry: false,
  });
}

export function useOrgRetention(org: string): UseQueryResult<RetentionPolicy> {
  return useQuery({
    queryKey: orgRetentionKey(org),
    queryFn: () => parsed(getOrgRetention({ path: { org } }), zRetentionPolicy),
    enabled: org !== '',
    retry: false,
  });
}

export function useProjectRetention(
  org: string,
  project: string,
): UseQueryResult<ProjectRetentionPolicy> {
  return useQuery({
    queryKey: projectRetentionKey(org, project),
    queryFn: () =>
      parsed(getProjectRetention({ path: { org, project } }), zProjectRetentionPolicy),
    enabled: org !== '' && project !== '',
    retry: false,
  });
}

type ProjectRetentionReadState =
  | { readonly status: 'pending' }
  | { readonly status: 'error'; readonly error: unknown }
  | { readonly status: 'ready'; readonly policy: ProjectRetentionPolicy };

/** Read every project's effective retention policy for the org-policy summary. */
export function useProjectRetentions(
  org: string,
  projects: readonly { readonly id: string }[],
): ReadonlyMap<string, ProjectRetentionReadState> {
  const results = useQueries({
    queries: projects.map((project) => ({
      queryKey: projectRetentionKey(org, project.id),
      queryFn: () =>
        parsed(
          getProjectRetention({ path: { org, project: project.id } }),
          zProjectRetentionPolicy,
        ),
      enabled: org !== '',
      retry: false,
    })),
  });

  const states = new Map<string, ProjectRetentionReadState>();
  projects.forEach((project, index) => {
    const result = results[index];
    if (result === undefined || result.isPending) {
      states.set(project.id, { status: 'pending' });
    } else if (result.isError) {
      states.set(project.id, { status: 'error', error: result.error });
    } else if (result.data === undefined) {
      states.set(project.id, {
        status: 'error',
        error: new Error('project retention query settled without a parsed policy'),
      });
    } else {
      states.set(project.id, { status: 'ready', policy: result.data });
    }
  });
  return states;
}

export type EnvironmentSettingsReadState =
  | { readonly status: 'pending' }
  | { readonly status: 'unreadable' }
  | { readonly status: 'forbidden' }
  | { readonly status: 'error'; readonly error: unknown }
  | {
      readonly status: 'ready';
      readonly protected: boolean;
      readonly reauth_window_seconds: number | null | undefined;
    };

type EnvironmentSettingsQueryResult = {
  readonly isPending: boolean;
  readonly isError: boolean;
  readonly data: EnvironmentSettings | undefined;
  readonly error: unknown;
};

/** Map one query result without collapsing pending or refusals into policy. */
export function environmentSettingsReadState(
  result: EnvironmentSettingsQueryResult | undefined,
): EnvironmentSettingsReadState {
  if (result === undefined || result.isPending) {
    return { status: 'pending' };
  }
  if (result.isError) {
    if (result.error instanceof ApiError && result.error.status === 404) {
      return { status: 'unreadable' };
    }
    if (result.error instanceof ApiError && result.error.status === 403) {
      return { status: 'forbidden' };
    }
    return { status: 'error', error: result.error };
  }
  if (result.data === undefined) {
    return {
      status: 'error',
      error: new Error('environment settings query settled without parsed settings'),
    };
  }
  return {
    status: 'ready',
    protected: result.data.protected,
    reauth_window_seconds: result.data.reauth_window_seconds,
  };
}

/** Shared query options: one resource, one key, one parsed boundary. */
export function environmentSettingsQueryOptions(
  org: string,
  project: string,
  environment: string,
  // Threaded so the matrix's per-environment settings fan-out reaches the
  // REMOTE inside a workspace (#71). Undefined is this instance's own server.
  client?: Client,
) {
  return {
    queryKey: environmentSettingsKey(org, project, environment),
    queryFn: () =>
      parsed(
        getEnvironmentSettings({ path: { org, project, environment }, client }),
        zEnvironmentSettings,
      ),
    enabled: org !== '' && project !== '' && environment !== '',
    retry: false,
  } as const;
}

/**
 * useEnvironmentSettings reads the per-environment policy for a whole project.
 *
 * One query per environment because that is what the API offers, and each is
 * its own authorization: `environment.settings-read` is `read@environment`, so
 * a member manager who holds no `read` gets a uniform 404 per environment.
 * Only that 404 is unreadable; pending, forbidden and faults stay distinct.
 */
export function useEnvironmentSettings(
  org: string,
  project: string,
  environments: readonly { id: string }[],
): ReadonlyMap<string, EnvironmentSettingsReadState> {
  const results = useQueries({
    queries: environments.map((env) => environmentSettingsQueryOptions(org, project, env.id)),
  });
  const map = new Map<string, EnvironmentSettingsReadState>();
  environments.forEach((env, index) => {
    map.set(env.id, environmentSettingsReadState(results[index]));
  });
  return map;
}

type QueryReadStatus = { readonly isPending: boolean; readonly isError: boolean };

/** Compute the one action gate from every hierarchy and settings dependency. */
export function orgTopologyReadiness(
  org: string,
  projects: QueryReadStatus,
  environments: readonly QueryReadStatus[],
  settings: readonly EnvironmentSettingsReadState[],
): { readonly isPending: boolean; readonly isError: boolean; readonly ready: boolean } {
  const isPending =
    projects.isPending ||
    environments.some((query) => query.isPending) ||
    settings.some((state) => state.status === 'pending');
  const isError =
    projects.isError ||
    environments.some((query) => query.isError) ||
    settings.some((state) => state.status === 'forbidden' || state.status === 'error');
  return { isPending, isError, ready: org !== '' && !isPending && !isError };
}

/**
 * useOrgTopology is the org's projects, their environments and each
 * environment's protection — the one shape the grant modal's scope select and
 * the org-scope blast enumeration both need. `ready` is the action gate: it is
 * true only after every hierarchy and settings read settled without a
 * forbidden or unexpected failure. Consumers must not open actions before it.
 *
 * It is deliberately the whole org rather than the active project: an
 * org-scoped grant reaches every project, and a warning that enumerated only
 * the project the human happened to be looking at would understate exactly the
 * thing it exists to state.
 */
export function useOrgTopology(org: string): {
  readonly projects: readonly ProjectNode[];
  readonly isPending: boolean;
  readonly isError: boolean;
  readonly ready: boolean;
} {
  const projects = useProjects(org);
  const items = projects.data === undefined ? [] : projects.data.items;

  const environments = useQueries({
    queries: items.map((project) => environmentListQueryOptions(org, project.id)),
  });

  const flat = items.flatMap((project, index) => {
    const result = environments[index];
    return result?.data === undefined
      ? []
      : result.data.items.map((env) => ({ project: project.id, env }));
  });

  const settings = useQueries({
    queries: flat.map(({ project, env }) =>
      environmentSettingsQueryOptions(org, project, env.id),
    ),
  });

  const protection = new Map<string, EnvironmentSettingsReadState>();
  flat.forEach(({ env }, index) => {
    protection.set(env.id, environmentSettingsReadState(settings[index]));
  });

  const { isPending, isError, ready } = orgTopologyReadiness(
    org,
    projects,
    environments,
    [...protection.values()],
  );

  const nodes: ProjectNode[] = ready
    ? items.map((project, index) => {
        const environmentResult = environments[index];
        if (environmentResult?.data === undefined) {
          throw new Error(`project ${project.id} settled without parsed environments`);
        }
        return {
          id: project.id,
          name: project.name,
          environments: environmentResult.data.items.map((env): EnvironmentNode => {
            const state = protection.get(env.id);
            if (state === undefined || state.status === 'pending') {
              throw new Error(`environment ${env.id} settled without settings state`);
            }
            return {
              id: env.id,
              name: env.name,
              isProtected: state.status === 'ready' ? state.protected : null,
            };
          }),
        };
      })
    : [];

  return {
    projects: nodes,
    isPending,
    isError,
    ready,
  };
}

// --- instance administration ------------------------------------------------

/**
 * useInstanceOrgs is the OPERATOR's enumeration of every organisation on the
 * instance — `instance-config`, which is MFA-mandatory.
 *
 * A password-only session is refused 403 here, and that refusal is rendered as
 * its own honest state rather than as an empty list: the answer is not "there
 * are no organisations", it is "this session has not presented a second
 * factor". The navigation rail asks a different question entirely
 * (`listMyOrgs`, #56) and needs no factor at all.
 */
export function useInstanceOrgs(): UseQueryResult<OrgList> {
  return useQuery({
    queryKey: orgsListKey,
    queryFn: () => parsed(listOrgs(), zOrgList),
    retry: false,
  });
}

export function useCreateOrg() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string }) =>
      parsed(createOrg({ body: { name: input.name } }), zOrg),
    onSettled: () => queries.invalidateQueries(),
  });
}

export function useDeleteOrg() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { org: string }) => ok(deleteOrg({ path: { org: input.org } })),
    onSettled: () => queries.invalidateQueries(),
  });
}

export function useRenameOrg() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { org: string; name: string }) =>
      parsed(renameOrg({ path: { org: input.org }, body: { name: input.name } }), zOrg),
    onSettled: () => queries.invalidateQueries(),
  });
}

export function useRenameProject(org: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { project: string; name: string }) =>
      parsed(
        renameProject({ path: { org, project: input.project }, body: { name: input.name } }),
        zProject,
      ),
    onSettled: () => queries.invalidateQueries(),
  });
}

export function useDeleteProject(org: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { project: string }) =>
      ok(deleteProject({ path: { org, project: input.project } })),
    onSettled: () => queries.invalidateQueries(),
  });
}

// --- authoring --------------------------------------------------------------

/**
 * useCreateProject writes one project into an organisation.
 *
 * On success it invalidates only the project list for this org — the exact key
 * every chrome surface reads through `useProjects` — so the new row appears
 * without a reload and nothing else refetches.
 */
export function useCreateProject(org: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string }) =>
      parsed(createProject({ path: { org }, body: { name: input.name } }), zProject),
    onSuccess: () => queries.invalidateQueries({ queryKey: projectsKey(org) }),
  });
}

/**
 * useCreateEnvironment writes one environment into a project.
 *
 * The invalidated key is `['environments', org, project]`, which is the single
 * key both this page's `useEnvironments` and the matrix's own read share, so a
 * created environment surfaces in the settings list AND the matrix at once.
 */
export function useCreateEnvironment(org: string, project: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string }) =>
      parsed(
        createEnvironment({ path: { org, project }, body: { name: input.name } }),
        zEnvironment,
      ),
    onSuccess: () => queries.invalidateQueries({ queryKey: environmentsKey(org, project) }),
  });
}

/**
 * createProjectRefusalText names the capability the act needs.
 *
 * A 403 and a 404 are deliberately the same sentence: whether the organisation
 * is unreachable or merely does not exist is a distinction the server refuses
 * to draw, and either way creating a project needs `manage-projects` at the
 * organisation scope.
 */
export function createProjectRefusalText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return error.detail ?? 'The project name is invalid.';
      case 401:
        return 'Your session ended. Sign in again to continue.';
      case 403:
      case 404:
        return 'You are not permitted to create a project here — that needs manage-projects at the organisation scope.';
      case 409:
        return error.detail ?? 'This project name is already in use.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return 'The server failed; whether the project was created is unknown — reload to check.';
    }
  }
  return 'The server failed; whether the project was created is unknown — reload to check.';
}

/**
 * createEnvironmentRefusalText is the environment counterpart: the same uniform
 * 403/404, and the capability it names is `definitions-edit` on the project.
 */
export function createEnvironmentRefusalText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return error.detail ?? 'The environment name is invalid.';
      case 401:
        return 'Your session ended. Sign in again to continue.';
      case 403:
      case 404:
        return 'You are not permitted to create an environment here — that needs definitions-edit on the project.';
      case 409:
        return error.detail ?? 'This environment name is already in use.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return 'The server failed; whether the environment was created is unknown — reload to check.';
    }
  }
  return 'The server failed; whether the environment was created is unknown — reload to check.';
}

/**
 * useRotateTokenKey is the one key operation with a network surface.
 *
 * Root, master and DEK rotation, `init`, `migrate`, restore reconciliation and
 * break-glass are LOCAL HOST AUTHORITY by the system-proof ADR and deliberately
 * have no UI and no API — the prototype's "Keys & crypto" card says so rather
 * than showing controls that could not exist.
 */
export function useRotateTokenKey() {
  return useMutation({ mutationFn: () => ok(rotateTokenKey()) });
}

// --- environment policy -----------------------------------------------------

export function useSetEnvironmentSettings(org: string, project: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      environment: string;
      protectedFlag: boolean;
      reauthWindowSeconds: number | null;
    }) =>
      parsed(
        setEnvironmentSettings({
          path: { org, project, environment: input.environment },
          body: {
            protected: input.protectedFlag,
            reauth_window_seconds: input.reauthWindowSeconds,
          },
        }),
        zEnvironmentSettings,
      ),
    onSettled: () => queries.invalidateQueries(),
  });
}

// --- retention --------------------------------------------------------------

export function useSetOrgRetention(org: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (policy: RetentionPolicy) =>
      parsed(setOrgRetention({ path: { org }, body: policy }), zRetentionPolicy),
    onSettled: () => queries.invalidateQueries(),
  });
}

export function useSetProjectRetention(org: string, project: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      inherited: boolean;
      maxAgeSeconds: number | null;
      lastRevisions: number | null;
    }) =>
      parsed(
        setProjectRetention({
          path: { org, project },
          body: {
            inherited: input.inherited,
            max_age_seconds: input.maxAgeSeconds,
            last_revisions: input.lastRevisions,
          },
        }),
        zProjectRetentionPolicy,
      ),
    onSettled: () => queries.invalidateQueries(),
  });
}

export const DAY_SECONDS = 86_400;

/** Format persisted seconds without rounding away policy. */
export function formatRetentionAge(seconds: number): string {
  if (seconds % DAY_SECONDS === 0) {
    const days = seconds / DAY_SECONDS;
    return `${days} ${days === 1 ? 'day' : 'days'}`;
  }
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  }
  return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;
}

export type RetentionDayState =
  | { readonly kind: 'days'; readonly days: string }
  | { readonly kind: 'exact'; readonly seconds: number }
  | { readonly kind: 'absent' };

/** Preserve whether a day-only editor can represent the persisted value. */
export function retentionDayState(seconds: number | null | undefined): RetentionDayState {
  if (seconds === null || seconds === undefined) {
    return { kind: 'absent' };
  }
  if (seconds % DAY_SECONDS !== 0) {
    return { kind: 'exact', seconds };
  }
  return { kind: 'days', days: String(seconds / DAY_SECONDS) };
}

type PositiveIntegerValidation =
  | { readonly ok: true; readonly value: number }
  | { readonly ok: false; readonly message: string };

/** Validate without coercing blank, fractional, negative or non-finite input. */
export function validatePositiveInteger(
  input: string,
  label: string,
): PositiveIntegerValidation {
  const value = Number(input);
  if (input.trim() === '' || !Number.isFinite(value) || !Number.isSafeInteger(value) || value < 1) {
    return { ok: false, message: `${label} must be a whole number of at least 1.` };
  }
  return { ok: true, value };
}

type RetentionBoundsPayload =
  | { readonly ok: true; readonly maxAgeSeconds: number; readonly lastRevisions: number }
  | { readonly ok: false; readonly message: string };

/** Validate and assemble the two bounded-retention payload dimensions once. */
export function retentionBoundsPayload(age: string, count: string): RetentionBoundsPayload {
  const validAge = validatePositiveInteger(age, 'Maximum age in days');
  if (!validAge.ok) {
    return validAge;
  }
  const validCount = validatePositiveInteger(count, 'Revision count');
  if (!validCount.ok) {
    return validCount;
  }
  const maxAgeSeconds = validAge.value * DAY_SECONDS;
  if (!Number.isSafeInteger(maxAgeSeconds)) {
    return { ok: false, message: 'Maximum age in days is too large to save exactly.' };
  }
  return { ok: true, maxAgeSeconds, lastRevisions: validCount.value };
}

/** Parse the project policy selector without treating an unknown value as override. */
export function projectRetentionInherited(value: string): boolean {
  if (value === 'inherit') {
    return true;
  }
  if (value === 'override') {
    return false;
  }
  throw new Error(`unknown project retention mode ${value}`);
}

/** retentionSentence is the effective policy in one readable line. */
export function retentionSentence(policy: RetentionPolicy): string {
  if (policy.mode === 'unlimited') {
    return 'Unlimited: payloads are never collected.';
  }
  const age = policy.max_age_seconds ?? null;
  const count = policy.last_revisions ?? null;
  if (age === null || count === null) {
    return 'Bounded, but this instance reported no bounds — that is a server fault, not a policy.';
  }
  return `Keep a payload while it is younger than ${formatRetentionAge(age)} OR among the last ${count} revisions of its environment.`;
}

export type SettingsOperation =
  | 'list-instance-orgs'
  | 'create-org'
  | 'get-credential-policy'
  | 'set-credential-policy'
  | 'get-retention-health'
  | 'rename-org'
  | 'delete-org'
  | 'rename-project'
  | 'delete-project'
  | 'set-org-retention'
  | 'set-project-retention'
  | 'set-environment-settings'
  | 'set-definitions-settings'
  | 'rotate-token-key';

class SettingsOperationFailure extends Error {
  readonly operation: SettingsOperation;
  readonly reason: unknown;

  constructor(operation: SettingsOperation, reason: unknown) {
    super(`settings operation ${operation} failed`);
    this.name = 'SettingsOperationFailure';
    this.operation = operation;
    this.reason = reason;
  }
}

/** Bind an asynchronous refusal to the operation that produced it. */
export function settingsOperationFailure(
  operation: SettingsOperation,
  error: unknown,
): Error {
  return new SettingsOperationFailure(operation, error);
}

/** Map each refusal using the operation that declared the status. */
export function settingsFailureText(
  error: unknown,
  operation?: SettingsOperation,
): string {
  const failure = error instanceof SettingsOperationFailure ? error.reason : error;
  const failedOperation =
    error instanceof SettingsOperationFailure ? error.operation : operation;
  if (failure instanceof ApiError) {
    switch (failure.status) {
      case 400:
        return failure.detail ?? invalidSettingsText(failedOperation);
      case 401:
        return 'Your session ended. Sign in again to continue.';
      case 403:
        return `You are not permitted to ${settingsAction(failedOperation)}.`;
      case 404:
        return unavailableSettingsText(failedOperation);
      case 409:
        return failure.detail ?? conflictingSettingsText(failedOperation);
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return 'The server failed; whether the change applied is unknown — reload to check.';
    }
  }
  return 'The server failed; whether the change applied is unknown — reload to check.';
}

function settingsAction(operation: SettingsOperation | undefined): string {
  switch (operation) {
    case 'list-instance-orgs':
      return 'list every organisation on this instance';
    case 'create-org':
      return 'create an organisation';
    case 'get-credential-policy':
      return 'read the machine-credential policy';
    case 'set-credential-policy':
      return 'change the machine-credential policy';
    case 'get-retention-health':
      return 'read retention health';
    case 'rename-org':
      return 'rename this organisation';
    case 'delete-org':
      return 'delete this organisation';
    case 'rename-project':
      return 'rename this project';
    case 'delete-project':
      return 'delete this project';
    case 'set-org-retention':
      return 'change this organisation retention policy';
    case 'set-project-retention':
      return 'change this project retention policy';
    case 'set-environment-settings':
      return 'change this environment policy';
    case 'set-definitions-settings':
      return 'change this project definitions source';
    case 'rotate-token-key':
      return 'rotate the change-token key';
    default:
      return 'perform this settings operation';
  }
}

function invalidSettingsText(operation: SettingsOperation | undefined): string {
  switch (operation) {
    case 'create-org':
      return 'The organisation name is invalid.';
    case 'rename-org':
      return 'The organisation name is invalid.';
    case 'rename-project':
      return 'The project name is invalid.';
    case 'set-org-retention':
      return 'The organisation retention policy is invalid; both bounded values must be positive.';
    case 'set-project-retention':
      return 'The project retention policy is invalid.';
    case 'set-environment-settings':
      return 'The environment policy is invalid.';
    case 'set-definitions-settings':
      return 'The definitions source is invalid.';
    case 'set-credential-policy':
      return 'The machine-credential policy is invalid.';
    default:
      return 'The server refused this request as invalid.';
  }
}

function unavailableSettingsText(operation: SettingsOperation | undefined): string {
  switch (operation) {
    case 'rename-org':
    case 'delete-org':
      return 'This organisation is unavailable or does not exist. Organisation lifecycle changes are instance-operator work.';
    case 'rename-project':
    case 'delete-project':
      return 'This project is unavailable or does not exist.';
    case 'set-org-retention':
      return 'This organisation retention policy is unavailable or does not exist.';
    case 'set-project-retention':
      return 'This project retention policy is unavailable or does not exist.';
    case 'set-environment-settings':
      return 'This environment policy is unavailable or does not exist.';
    case 'set-definitions-settings':
      return 'This project definitions policy is unavailable or does not exist.';
    case 'list-instance-orgs':
      return 'The instance organisation listing is unavailable.';
    case 'get-credential-policy':
    case 'set-credential-policy':
      return 'The machine-credential policy is unavailable.';
    case 'get-retention-health':
      return 'Retention health is unavailable.';
    case 'rotate-token-key':
      return 'The change-token key rotation is unavailable.';
    default:
      return 'This settings resource is unavailable or does not exist.';
  }
}

function conflictingSettingsText(operation: SettingsOperation | undefined): string {
  switch (operation) {
    case 'create-org':
      return 'This organisation name is already in use.';
    case 'rename-org':
      return 'This organisation name is already in use.';
    case 'rename-project':
      return 'This project name is already in use.';
    case 'delete-org':
      return 'Deletion never cascades: this organisation still holds projects or grants.';
    case 'delete-project':
      return 'Deletion never cascades: this project still holds environments or folders.';
    case 'set-environment-settings':
      return 'The current environment state refused this policy change. Reload before retrying.';
    default:
      return 'The current resource state refused this settings change. Reload before retrying.';
  }
}
