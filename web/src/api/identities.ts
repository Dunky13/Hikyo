import {
  createEnvGrant,
  createFederatedBinding,
  listKeys,
  listMachineCredentials,
  listProjectGrants,
  listServiceAccounts,
  mintMachineCredential,
  revokeMachineCredential,
  type FederatedClaimPin,
} from '@hikyo/client';
import {
  zFederatedBinding,
  zGrantList,
  zGrantResult,
  zKeyList,
  zMachineCredentialList,
  zMintCredentialResult,
  zServiceAccountList,
} from '@hikyo/zod';
import { useMutation, useQueries, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ApiError, parsed } from './client.ts';

/**
 * The machine-access surface, as the SPA sees it (#67, locked prototype #31
 * iteration 3).
 *
 * Everything here crosses its generated schema before a component sees it, and
 * two of this file's rules exist because the ADRs put them here rather than in
 * the component:
 *
 *  - **A credential value exists in exactly one response.** `MachineCredential`
 *    has no value member and no route returns one after the mint, so the only
 *    place plaintext can enter the SPA is `useMintCredential`'s result — which
 *    is why the mint dialog is the only component that ever holds one.
 *  - **The post-state reach is what the mint's formula ranges over**, not what
 *    the mint adds. A mint adds no grants, so the post-state IS the current
 *    state: the environments the service account can already decrypt. That set
 *    decides whether the human must reauthenticate, and it is computed from the
 *    server's grant rows rather than guessed.
 */

export type ServiceAccount = z.infer<typeof zServiceAccountList>['items'][number];
export type MachineCredential = z.infer<typeof zMachineCredentialList>['items'][number];
export type Grant = z.infer<typeof zGrantList>['items'][number];
/**
 * ClaimPin is the READ shape — the parsed one, whose `number_value` is a bigint
 * because an int64 repository id does not survive a float. The REQUEST shape is
 * the generated `FederatedClaimPin`, which carries a plain number: they are two
 * different types on purpose and neither is re-declared here.
 */
export type ClaimPin = NonNullable<MachineCredential['required_claims']>[number];

export type ProjectRef = { org: string; project: string };

const accountsKey = (p: ProjectRef) => ['service-accounts', p.org, p.project] as const;
const credentialsKey = (p: ProjectRef, sa: string) =>
  ['machine-credentials', p.org, p.project, sa] as const;
const projectGrantsKey = (p: ProjectRef) => ['project-grants', p.org, p.project] as const;

/** useServiceAccounts lists the project's machine principals. Metadata only. */
export function useServiceAccounts(
  p: ProjectRef,
): UseQueryResult<z.infer<typeof zServiceAccountList>> {
  return useQuery({
    queryKey: accountsKey(p),
    queryFn: () =>
      parsed(listServiceAccounts({ path: { org: p.org, project: p.project } }), zServiceAccountList),
    retry: false,
  });
}

/**
 * useProjectGrants is how the surface learns each service account's SCOPE.
 *
 * It is a separate query from the account listing because it is a separate
 * authority: listing accounts is `manage-identities`, and the membership
 * surface is `manage-members`. A principal who administers identities but not
 * members gets the accounts and an honest "scope unavailable" rather than a
 * blank column that reads like "no grants".
 */
export function useProjectGrants(p: ProjectRef): UseQueryResult<z.infer<typeof zGrantList>> {
  return useQuery({
    queryKey: projectGrantsKey(p),
    queryFn: () =>
      parsed(listProjectGrants({ path: { org: p.org, project: p.project } }), zGrantList),
    retry: false,
  });
}

/**
 * useKeyCatalogue is the grant warning's blast-radius source: every key's name
 * and classification, and NOTHING with a value member.
 *
 * Deliberately `listKeys`, not `listValues`: a value listing is authorized for
 * the HUMAN reading it, so it carries config plaintext this surface never
 * renders — and a fetch is a copy, cached by the query client where any
 * same-page script can read it. The catalogue endpoint answers the only
 * question the warning asks (what exists, of which classification) without
 * ever holding a value of any kind.
 */
export function useKeyCatalogue(p: ProjectRef): UseQueryResult<z.infer<typeof zKeyList>> {
  return useQuery({
    queryKey: ['key-catalogue', p.org, p.project] as const,
    queryFn: () => parsed(listKeys({ path: { org: p.org, project: p.project } }), zKeyList),
    retry: false,
  });
}

type CredentialsByAccount = {
  readonly byAccount: ReadonlyMap<string, readonly MachineCredential[]>;
  readonly isPending: boolean;
  readonly isError: boolean;
};

/**
 * useCredentials fetches every account's credential rows.
 *
 * All of them, not just the expanded row: the Federation tab is the same rows
 * filtered by kind, and the tab counts are the sizes of those sets — so a
 * fetch-on-expand would leave the tabs unable to say how much they hold.
 */
export function useCredentials(
  p: ProjectRef,
  accounts: readonly ServiceAccount[],
): CredentialsByAccount {
  return useQueries({
    queries: accounts.map((sa) => ({
      queryKey: credentialsKey(p, sa.id),
      queryFn: () =>
        parsed(
          listMachineCredentials({
            path: { org: p.org, project: p.project, serviceAccount: sa.id },
          }),
          zMachineCredentialList,
        ),
      retry: false,
    })),
    combine: (results) => ({
      byAccount: new Map(
        accounts.map((sa, index) => [sa.id, results[index]?.data?.items ?? []] as const),
      ),
      isPending: results.some((r) => r.isPending),
      isError: results.some((r) => r.isError),
    }),
  });
}

/**
 * zMinted is the mint result NARROWED to what a caller may keep.
 *
 * Deliberately not the whole `MintCredentialResult`: the nested credential
 * metadata is re-read from the listing a moment later anyway, and parsing it
 * here would let a drift in an unrelated member throw away the one member
 * nothing in the system can ever return again. `clamped` stays because the
 * operator has to be told the ceiling shortened what they asked for rather than
 * discover it when the credential dies early.
 */
const zMinted = zMintCredentialResult.pick({ value: true, clamped: true });

/**
 * mintCredential is the display-once mint, and it is deliberately NOT a
 * `useMutation`.
 *
 * TanStack keeps a mutation's result in a global cache until garbage
 * collection, so a mint run through it would leave the plaintext credential
 * reachable from the query client long after the dialog that showed it closed —
 * a second copy of a value whose whole contract is that there is one. A plain
 * async call leaves the value in exactly one place: the component that renders
 * it once.
 */
export async function mintCredential(
  p: ProjectRef,
  serviceAccount: string,
): Promise<z.infer<typeof zMinted>> {
  return parsed(
    mintMachineCredential({
      path: { org: p.org, project: p.project, serviceAccount },
      body: {},
    }),
    zMinted,
  );
}

/**
 * useRefreshAccount re-reads what a mint changed.
 *
 * It exists because the mint above is not a mutation and therefore has no
 * `onSuccess` — and because a mint whose response never arrived may still have
 * COMMITTED, so the caller has to be able to refresh on the failure path too.
 */
export function useRefreshAccount(p: ProjectRef): (serviceAccount: string) => void {
  const queries = useQueryClient();
  return (serviceAccount: string) => {
    void queries.invalidateQueries({ queryKey: credentialsKey(p, serviceAccount) });
    void queries.invalidateQueries({ queryKey: accountsKey(p) });
  };
}

/**
 * useRefreshGrants re-reads the scope surface, for the same reason
 * useRefreshAccount exists: a grant whose response never arrived may still
 * have COMMITTED, and a committed widening must show in the scope column even
 * when the dialog reports a failure.
 */
export function useRefreshGrants(p: ProjectRef): () => void {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: projectGrantsKey(p) });
  };
}

/**
 * useRevokeCredential retires one credential. It is NOT deprovisioning: grants
 * are untouched and siblings keep working, which is what makes rotation
 * (mint, distribute, then revoke) a sequence of two deliberate acts.
 */
export function useRevokeCredential(p: ProjectRef) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async (input: { serviceAccount: string; credential: string }) => {
      const result = await revokeMachineCredential({
        path: {
          org: p.org,
          project: p.project,
          serviceAccount: input.serviceAccount,
          credential: input.credential,
        },
      });
      if (!result.response.ok) {
        throw new ApiError(result.response.status, `revoke failed with ${result.response.status}`);
      }
    },
    onSuccess: (_void, input) => {
      void queries.invalidateQueries({ queryKey: credentialsKey(p, input.serviceAccount) });
      void queries.invalidateQueries({ queryKey: accountsKey(p) });
    },
  });
}

/** useCreateBinding mints a federated `(issuer, subject)` binding. */
export function useCreateBinding(p: ProjectRef) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      serviceAccount: string;
      issuer: string;
      subject: string;
      audience: string;
      requiredClaims: readonly FederatedClaimPin[];
      lifetimeSeconds?: number;
    }) =>
      parsed(
        createFederatedBinding({
          path: { org: p.org, project: p.project, serviceAccount: input.serviceAccount },
          body: {
            issuer: input.issuer,
            subject: input.subject,
            audience: input.audience,
            required_claims: input.requiredClaims.map((pin) => ({ ...pin })),
            ...(input.lifetimeSeconds === undefined
              ? {}
              : { lifetime_seconds: input.lifetimeSeconds }),
          },
        }),
        zFederatedBinding,
      ),
    onSuccess: (_result, input) => {
      void queries.invalidateQueries({ queryKey: credentialsKey(p, input.serviceAccount) });
      // A binding IS a live credential, so the account's `live_credentials` —
      // the number the grant warning quotes — moved too.
      void queries.invalidateQueries({ queryKey: accountsKey(p) });
    },
  });
}

/**
 * useGrantEnvironment adds one capability to a machine principal on one
 * environment. The warning the caller shows first is not decoration: the grant
 * attaches to the SERVICE ACCOUNT, so every credential already in circulation
 * is re-scoped the moment it lands.
 */
export function useGrantEnvironment(p: ProjectRef) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { environment: string; principal: string; capability: string }) =>
      parsed(
        createEnvGrant({
          path: { org: p.org, project: p.project, environment: input.environment },
          body: { principal: input.principal, capability: input.capability },
        }),
        zGrantResult,
      ),
    onSuccess: () => queries.invalidateQueries({ queryKey: projectGrantsKey(p) }),
  });
}

// --- derivation, all of it pure --------------------------------------------

export type EnvironmentRef = { readonly id: string; readonly name: string };

/** MachineEnvScope is what one service account reaches in one environment. */
export type MachineEnvScope = {
  readonly id: string;
  readonly name: string;
  /** `read` delivers configuration and secret PRESENCE — never plaintext. */
  readonly read: boolean;
  /** `reveal` is the standing decryption capability, the ◆ in the prototype. */
  readonly reveal: boolean;
};

/**
 * scopeOf resolves a principal's grant rows into per-environment reach.
 *
 * A row with no `environment_id` is PROJECT-scoped and reaches every
 * environment beneath it — the ordinary downward inheritance. The listing this
 * reads is already confined to one project, so there is no wider row to
 * mistake for a narrow one.
 */
export function scopeOf(
  grants: readonly Grant[],
  principalId: string,
  environments: readonly EnvironmentRef[],
): MachineEnvScope[] {
  const mine = grants.filter((g) => g.principal_id === principalId);
  const holds = (capability: string, environment: string) =>
    mine.some(
      (g) =>
        g.capability === capability &&
        (g.scope.environment_id === undefined || g.scope.environment_id === environment),
    );
  return environments.map((env) => ({
    id: env.id,
    name: env.name,
    read: holds('read', env.id),
    reveal: holds('reveal', env.id),
  }));
}

/**
 * postStateReach is the environments a credential of this account can decrypt
 * — the set the mint's disclosure conjunct ranges over.
 *
 * `read` is required as well as `reveal`, mirroring the server: no read means
 * no delivery at all, so neither disclosure capability reaches plaintext
 * however it is granted.
 */
export function postStateReach(scope: readonly MachineEnvScope[]): MachineEnvScope[] {
  return scope.filter((s) => s.read && s.reveal);
}

/**
 * grantWideningReach is the mint's conjunct for a GRANT: the environments the
 * account would newly decrypt, not the whole post-state.
 *
 * The difference is the ADR's, not a nuance: a mint adds no grants, so its
 * formula ranges over everything the account already reaches; a grant adds one,
 * so its formula ranges over the DELTA. `checkMachineWidening` computes exactly
 * this server-side, and a client that asked for a ceremony over the whole
 * post-state would prompt for authority the server never consumes.
 *
 * For a `read` grant the delta is empty unless the account already holds
 * `reveal` there — which is why it is vacuous today: the machine allowlist
 * admits `read` and nothing else on a workload principal.
 */
export function grantWideningReach(
  scope: readonly MachineEnvScope[],
  environmentId: string,
  capability: 'read' | 'reveal',
): MachineEnvScope[] {
  const after = scope.map((s) =>
    s.id === environmentId
      ? { ...s, read: s.read || capability === 'read', reveal: s.reveal || capability === 'reveal' }
      : s,
  );
  const before = new Set(postStateReach(scope).map((s) => s.id));
  return postStateReach(after).filter((s) => !before.has(s.id));
}

/**
 * parseClaimNumber turns a typed int64 pin into a number, or refuses.
 *
 * `Number()` is not usable here and the failures are not cosmetic: an empty
 * field becomes 0, which is a valid-looking repository id nobody owns; `1e3`
 * and `4242.7` are accepted; and anything past 2^53 silently rounds to a
 * NEIGHBOURING repository id — which would bind a production service account to
 * whatever repository happens to hold that number. Digits only, and inside the
 * range JSON can carry losslessly.
 */
export function parseClaimNumber(raw: string): number | null {
  if (!/^-?[0-9]+$/.test(raw.trim())) {
    return null;
  }
  const value = Number(raw.trim());
  return Number.isSafeInteger(value) ? value : null;
}

/**
 * dismissDecision is what a dismissal attempt on the mint dialog does.
 *
 * Three outcomes, and the first is the one that is easy to miss: **while the
 * mint is in flight there is no dismissal at all.** Escape reaches a native
 * `<dialog>` even when the Cancel button is disabled, and unmounting mid-flight
 * would let a value the server DID commit arrive at a component that no longer
 * exists — losing it exactly as thoroughly as never minting it, while leaving a
 * live credential behind. After that, a shown value holds the dialog open until
 * the operator confirms they stored it, because there is no second look.
 *
 * It is a function rather than three `if`s in a handler so the rule can be
 * checked without a DOM: the failure it guards against is invisible in a
 * screenshot.
 */
export function dismissDecision(input: {
  busy: boolean;
  hasValue: boolean;
  stored: boolean;
}): 'ignore' | 'hold-back' | 'close' {
  if (input.busy) {
    return 'ignore';
  }
  if (input.hasValue && !input.stored) {
    return 'hold-back';
  }
  return 'close';
}

/** isoDay renders an instant as the calendar day, which is all these surfaces show. */
export function isoDay(timestamp: string): string {
  return timestamp.slice(0, 10);
}

export type JourneyState = 'done' | 'next' | 'unavailable';

export type JourneyStep = {
  readonly title: string;
  readonly note: string;
  readonly state: JourneyState;
};

/**
 * setupJourney is the five-step workload-integration journey (#18, the locked
 * prototype's rail), told against what this build can actually do.
 *
 * Steps 4 and 5 are `unavailable` rather than `next`, and that is the honest
 * rendering: the per-project machine-reveal opt-in has no server surface yet,
 * and the permission model's machine allowlist admits `read` and nothing else
 * on a workload principal — so a "grant reveal" button would be a control that
 * is refused every time it is pressed. The prototype's verbatim delivery
 * refusal is left out for the same reason: this build's delivery never refuses,
 * it delivers configuration and secret presence, and rendering a refusal would
 * describe a state the server does not produce.
 *
 * `null` for an automation principal: automation never delivers to a workload,
 * so it has no setup journey at all.
 */
export function setupJourney(
  kind: 'workload' | 'automation',
  scope: readonly MachineEnvScope[],
): JourneyStep[] | null {
  if (kind === 'automation') {
    return null;
  }
  const read = scope.filter((s) => s.read);
  const named = read.map((s) => s.name).join(', ');
  return [
    {
      title: 'Service account minted',
      note: 'kind: workload — immutable at creation',
      state: 'done',
    },
    {
      title:
        read.length === 0
          ? 'Grant read on an environment'
          : `read granted — ${named}`,
      note: 'delivers configuration and secret presence only',
      state: read.length === 0 ? 'next' : 'done',
    },
    {
      title:
        read.length === 0
          ? 'First delivery'
          : 'First delivery succeeds — configuration and secret presence',
      note: 'a fetch that delivers no values is still an audited access record',
      state: read.length === 0 ? 'next' : 'done',
    },
    {
      title: 'Project machine-reveal opt-in',
      note: 'not part of this build: the per-project opt-in that admits a standing decryption capability has no server surface yet (#17/#18)',
      state: 'unavailable',
    },
    {
      title: 'Grant reveal',
      note: 'not part of this build: a workload principal may hold read and nothing else until the opt-in lands, so no credential here reaches plaintext',
      state: 'unavailable',
    },
  ];
}

/**
 * expiryLabel is the in-product-first expiry signal (#17): the product says so
 * before any email does, and it says it in words rather than in a colour.
 */
export function expiryLabel(credential: MachineCredential, now: Date): string {
  if (credential.revoked_at !== undefined) {
    return 'revoked';
  }
  if (credential.lifetime === 'indefinite') {
    return 'no expiry';
  }
  if (credential.expires_at === undefined) {
    return 'expiry unknown';
  }
  const days = Math.ceil((new Date(credential.expires_at).getTime() - now.getTime()) / 86_400_000);
  if (days <= 0) {
    return 'expired';
  }
  return `expires in ${String(days)} ${days === 1 ? 'day' : 'days'}`;
}

/** lastUsedLabel keeps "never used" and "used at the epoch" different facts. */
export function lastUsedLabel(credential: MachineCredential): string {
  return credential.last_used_at === undefined
    ? 'never used'
    : `last used ${isoDay(credential.last_used_at)}`;
}

export type IssuerPlatform = 'kubernetes' | 'forgejo' | 'github-actions';

export type ClaimField = {
  readonly claim: string;
  readonly label: string;
  readonly kind: 'string' | 'number' | 'event';
};

export type FederationPreset = {
  readonly id: IssuerPlatform;
  readonly label: string;
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  /**
   * The claims this platform's bindings MUST pin, which the server refuses a
   * binding without. They are fields rather than fixed values because the
   * immutable identifiers are per-repository and per-cluster.
   */
  readonly claims: readonly ClaimField[];
};

/**
 * FEDERATION_PRESETS carry the per-platform pin rules the server enforces at
 * binding creation, so the form asks for them rather than letting the operator
 * discover them as a 400.
 *
 * Kubernetes pins the ServiceAccount UID through its JSON Pointer — a
 * recreated ServiceAccount with the same name has a different UID, which is
 * precisely what the pin closes. The two CI platforms must pin `event_name`,
 * and GitHub Actions additionally pins the numeric repository ids, because a
 * renamed-and-reused repository path would otherwise inherit the binding.
 */
export const KUBERNETES_PRESET: FederationPreset = {
  id: 'kubernetes',
  label: 'Kubernetes ServiceAccount token',
  issuer: 'https://kubernetes.default.svc.cluster.local',
  subject: 'system:serviceaccount:hikyo-system:hikyo-fetch',
  audience: '',
  claims: [
    { claim: '/kubernetes.io/serviceaccount/uid', label: 'ServiceAccount UID', kind: 'string' },
  ],
};

const FORGEJO_PRESET: FederationPreset = {
  id: 'forgejo',
  label: 'Forgejo Actions',
  issuer: 'https://git.example.org',
  subject: 'repo:owner/repository:ref:refs/heads/main',
  audience: '',
  claims: [
    { claim: 'repository', label: 'Repository', kind: 'string' },
    { claim: 'event_name', label: 'Event name', kind: 'event' },
  ],
};

const GITHUB_ACTIONS_PRESET: FederationPreset = {
  id: 'github-actions',
  label: 'GitHub Actions',
  issuer: 'https://token.actions.githubusercontent.com',
  subject: 'repo:owner/repository:ref:refs/heads/main',
  audience: '',
  claims: [
    { claim: 'repository_id', label: 'Repository id', kind: 'number' },
    { claim: 'repository_owner_id', label: 'Repository owner id', kind: 'number' },
    { claim: 'event_name', label: 'Event name', kind: 'event' },
  ],
};

export const FEDERATION_PRESETS: readonly FederationPreset[] = [
  KUBERNETES_PRESET,
  FORGEJO_PRESET,
  GITHUB_ACTIONS_PRESET,
];

/** presetFieldId keeps a JSON-Pointer claim usable as an element id. */
export function presetFieldId(claim: string): string {
  return `binding-${claim.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`;
}

/**
 * BINDING_LIFETIMES is the binding's own lifetime, which is #17's rule rather
 * than a convenience: a binding is a standing permission to present tokens and
 * expires on the same terms as a bearer credential — renewal is a mint, never
 * an edit, because bindings are immutable.
 *
 * `indefinite` is present and DISABLED with its reason, exactly as the frozen
 * prototype has it: the instance opt-in that admits it is off by default, and a
 * missing option would leave an operator wondering whether the product has the
 * concept at all.
 */
export const BINDING_LIFETIMES: ReadonlyArray<{
  readonly id: string;
  readonly label: string;
  readonly seconds?: number;
  readonly disabled?: boolean;
}> = [
  { id: 'default', label: 'Instance default' },
  { id: '30d', label: '30 days', seconds: 30 * 24 * 60 * 60 },
  { id: '90d', label: '90 days', seconds: 90 * 24 * 60 * 60 },
  {
    id: 'indefinite',
    label: 'Indefinite — requires the instance allow_indefinite opt-in',
    disabled: true,
  },
];

/** The events a CI binding can pin. The last two are the refused pair. */
export const CI_EVENTS = ['push', 'workflow_dispatch', 'pull_request', 'pull_request_target'] as const;

/**
 * pullRequestRefusal names why a pull-request binding is refused.
 *
 * The protection comes from the PINNED EVENT, never from the subject's shape:
 * a `pull_request_target` token carries the ordinary ref-form subject — the
 * default branch's, the one a production binding names — so a binding that
 * pinned only the subject would already be reachable from a pull request.
 * Returning the sentence rather than a boolean keeps what is shown and what is
 * refused as one thing.
 */
export function pullRequestRefusal(eventName: string): string | null {
  if (eventName !== 'pull_request' && eventName !== 'pull_request_target') {
    return null;
  }
  return (
    `Refused: this binding pins event_name ${eventName}. A pull-request workflow runs ` +
    `third-party code, so binding it hands every pull-request author this service ` +
    `account's fetch authority.`
  );
}

/**
 * identityRefusalText names what actually happened, in the vocabulary of the
 * act that failed. A machine-identity refusal is never "your access may have
 * changed" — the caller holds `manage-identities` or they never saw the page.
 */
export function identityRefusalText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return 'The server refused that as malformed. Check the issuer, subject, audience and the pinned claims — every one of them is matched byte-for-byte.';
      case 403:
        return 'The server refused this act. Minting or binding needs a disclosure capability over every environment the account reaches in the resulting state, plus a fresh reauthentication.';
      case 404:
        return 'That service account is no longer here.';
      case 409:
        return 'The server refused this as a conflict: the live-credential ceiling, or an identical binding that already exists.';
      case 429:
        return 'Too many requests right now. Wait a moment and try again.';
      default:
        return `The act could not be completed (server error ${String(error.status)}).`;
    }
  }
  if (error instanceof Error && error.name === 'NotAllowedError') {
    return 'The passkey prompt was dismissed or timed out. Nothing was minted.';
  }
  return 'The act could not be completed.';
}

/**
 * mintFailureText is the refusal for a mint request that WAS ISSUED.
 *
 * It is a different sentence from `identityRefusalText` because the honest
 * answer is different: once the request left, a failure carries no information
 * about whether the server committed — a transport that dropped the response,
 * or a body this build could not parse, both leave a credential that may exist
 * and whose value is gone forever. Saying "the mint failed" there would be a
 * guess, and the wrong one leaves a live credential nobody is looking for.
 */
export function mintFailureText(error: unknown): string {
  return `${identityRefusalText(error)} A credential may still have been minted: its value is not recoverable, so check the rows below and revoke anything you did not expect.`;
}

/**
 * bindingFailureText is the same issued-not-confirmed honesty for a binding: a
 * lost response may still have created a live external login path, and the row
 * list is the only place it would show.
 */
export function bindingFailureText(error: unknown): string {
  return `${identityRefusalText(error)} The binding may still have been created: check the account's rows and revoke anything you did not expect.`;
}

/**
 * grantFailureText: a lost response may still have widened every live
 * credential's reach, which is exactly the change the warning existed to make
 * deliberate — so it must not be reported as "nothing happened".
 */
export function grantFailureText(error: unknown): string {
  return `${identityRefusalText(error)} The grant may still have landed: the scope column shows what the account reaches now, so check it before acting again.`;
}
