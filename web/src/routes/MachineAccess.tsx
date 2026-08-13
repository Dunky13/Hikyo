import { useEffect, useMemo, useRef, useState, type MutableRefObject, type ReactNode } from 'react';
import { useParams } from 'react-router';

import type { FederatedClaimPin } from '@hikyo/client';

import {
  BINDING_LIFETIMES,
  bindingFailureText,
  CI_EVENTS,
  dismissDecision,
  expiryLabel,
  FEDERATION_PRESETS,
  grantFailureText,
  grantWideningReach,
  identityRefusalText,
  isoDay,
  KUBERNETES_PRESET,
  lastUsedLabel,
  mintCredential,
  mintFailureText,
  parseClaimNumber,
  postStateReach,
  presetFieldId,
  pullRequestRefusal,
  scopeOf,
  setupJourney,
  useCreateBinding,
  useCredentials,
  useGrantEnvironment,
  useKeyCatalogue,
  useProjectGrants,
  useRefreshAccount,
  useRefreshGrants,
  useRevokeCredential,
  useServiceAccounts,
  type ClaimPin,
  type FederationPreset,
  type MachineCredential,
  type MachineEnvScope,
  type ProjectRef,
  type ServiceAccount,
} from '../api/identities.ts';
import { runPasskeyCeremony, useEnvironments } from '../api/values.ts';

/**
 * The machine-access surface (#67, locked prototype #31 iteration 3).
 *
 * The structure is the prototype's, and each part of it is a rule rather than a
 * layout preference:
 *
 *  - **A tabbed inventory** — service accounts, federation, Kubernetes targets
 *    — with the per-project machine-reveal policy stated above the table.
 *  - **Write-only credential rows.** Prefix hint, kind, expiry in words,
 *    last used. Never the value: no route returns one after the mint, so there
 *    is nothing here that could render it.
 *  - **Row expansion leads with credentials and bindings (left), delivery
 *    targets and actions (right), and the five-step setup journey full-width
 *    below** — iteration 3's resolution, journey underneath rather than on top.
 *  - **Display-once mint.** A step-up naming the post-state formula, then the
 *    value exactly once, with a stored-confirmation checkbox gating dismiss.
 *    Rotation is the same flow: the prior value is never returned.
 *
 * Where the prototype is ahead of the server this surface says so instead of
 * pretending. The three places, each recorded in `docs/handoff/67-machine-access.md`:
 * the per-project reveal opt-in has no server surface, Kubernetes delivery
 * targets have no operator reporting them, and restore reconciliation has no
 * recovery-mode signal — only the binding's own quarantine field, which IS
 * rendered because it is real.
 */

type Tab = 'accounts' | 'federation' | 'kubernetes';

type Dialog =
  | { kind: 'mint'; account: ServiceAccount; rotating: boolean }
  | { kind: 'binding'; account: ServiceAccount }
  | { kind: 'grant'; account: ServiceAccount };

const TABS: ReadonlyArray<{ id: Tab; label: string }> = [
  { id: 'accounts', label: 'Service accounts' },
  { id: 'federation', label: 'Federation' },
  { id: 'kubernetes', label: 'Kubernetes targets' },
];

export function MachineAccess() {
  const params = useParams();
  const project: ProjectRef = {
    org: params['org'] ?? '',
    project: params['project'] ?? '',
  };

  const accountsQuery = useServiceAccounts(project);
  const grantsQuery = useProjectGrants(project);
  const environmentsQuery = useEnvironments({ ...project, environment: '' });

  const accounts = useMemo(() => accountsQuery.data?.items ?? [], [accountsQuery.data]);
  const environments = useMemo(
    () => environmentsQuery.data?.items ?? [],
    [environmentsQuery.data],
  );
  const grants = useMemo(() => grantsQuery.data?.items ?? [], [grantsQuery.data]);
  const credentials = useCredentials(project, accounts);

  const [tab, setTab] = useState<Tab>('accounts');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const revoke = useRevokeCredential(project);
  const now = useMemo(() => new Date(), []);

  const scopeFor = (sa: ServiceAccount): MachineEnvScope[] =>
    scopeOf(grants, sa.principal_id, environments);
  const credentialsFor = (sa: ServiceAccount): readonly MachineCredential[] =>
    credentials.byAccount.get(sa.id) ?? [];
  // Un-revoked, which is NOT the same as live: an expired credential is
  // revoked_at-less and authenticates nothing. The count an operator is told is
  // the server's own `live_credentials`, which applies the whole liveness
  // predicate — epoch, revocation and expiry. This filter only decides which
  // rows are worth showing.
  const showable = (rows: readonly MachineCredential[]) =>
    rows.filter((c) => c.revoked_at === undefined);
  const bearers = (rows: readonly MachineCredential[]) =>
    showable(rows).filter((c) => c.kind === 'hikyo-token');
  const bindings = (rows: readonly MachineCredential[]) =>
    showable(rows).filter((c) => c.kind === 'oidc-federation');

  const allBindings = accounts.flatMap((sa) =>
    bindings(credentialsFor(sa)).map((credential) => ({ account: sa, credential })),
  );

  /**
   * inputsReady gates every act on the surface.
   *
   * Each dialog's warning is an assertion about state — how many credentials a
   * grant re-scopes, which environments a mint's formula ranges over — and a
   * query that failed answers those questions with a confident zero. Refusing
   * to act on a half-read surface is the only honest option: the alternative is
   * a warning that understates what the operator is about to do.
   */
  const inputsReady =
    accountsQuery.isSuccess &&
    grantsQuery.isSuccess &&
    environmentsQuery.isSuccess &&
    !credentials.isPending &&
    !credentials.isError;

  const tabCount: Record<Tab, string> = {
    accounts: accountsQuery.isSuccess ? String(accounts.length) : '—',
    // Unknown is rendered as unknown: "Federation (0)" on a failed listing
    // reads as "there are none", which is the one thing it does not know.
    federation: credentials.isPending || credentials.isError ? '—' : String(allBindings.length),
    kubernetes: '0',
  };

  const doRevoke = (account: ServiceAccount, credential: MachineCredential) => {
    setRefusal(null);
    revoke.mutate(
      { serviceAccount: account.id, credential: credential.id },
      {
        onSuccess: () =>
          setNotice(
            'Revoked. It stops authenticating at the next request, never at expiry — grants and sibling credentials are untouched.',
          ),
        onError: (error) => setRefusal(identityRefusalText(error)),
      },
    );
  };

  return (
    <section className="card card--wide machine" aria-labelledby="machine-title">
      <header className="values__head">
        <h1 id="machine-title">Machine access</h1>
      </header>

      {accountsQuery.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            The service accounts could not be listed. Listing them needs manage-identities on this
            project.
          </span>
        </p>
      ) : null}

      {grantsQuery.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            The grant rows could not be read, so no scope is shown below. Reading the membership
            surface needs manage-members on this project — a separate authority from administering
            identities.
          </span>
        </p>
      ) : null}

      {environmentsQuery.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            The project&apos;s environments could not be read, so no scope is shown below — an empty
            scope column here would say &ldquo;this account reaches nothing&rdquo;, which is not
            something this page knows.
          </span>
        </p>
      ) : null}

      {credentials.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            At least one service account&apos;s credentials could not be listed. Counts and the
            federation tab are incomplete, and the actions are held back until the listing succeeds.
          </span>
        </p>
      ) : null}

      {refusal !== null ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{refusal}</span>
        </p>
      ) : null}

      {credentials.isPending && !credentials.isError && accounts.length > 0 ? (
        <p className="notice" role="status">
          <span className="alert__glyph" aria-hidden="true">
            ⋯
          </span>
          <span>Reading credentials…</span>
        </p>
      ) : null}

      {notice !== null ? (
        <p className="notice" role="status">
          <span className="alert__glyph" aria-hidden="true">
            ✓
          </span>
          <span>{notice}</span>
        </p>
      ) : null}

      <div className="tabs" role="tablist" aria-label="Machine access sections">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            id={`machine-tab-${entry.id}`}
            className="tab"
            aria-selected={tab === entry.id}
            aria-controls="machine-panel"
            onClick={() => setTab(entry.id)}
          >
            {`${entry.label} (${tabCount[entry.id]})`}
          </button>
        ))}
      </div>

      <div className="tabpanel" role="tabpanel" id="machine-panel" aria-labelledby={`machine-tab-${tab}`}>
        {tab === 'accounts' ? (
          <>
            <PolicyStrip />
            <table className="values__table machine__table">
              <caption className="visually-hidden">
                The project&apos;s service accounts. Credential values are never listed: a value is
                displayed once, at mint.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Service account</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Read scope (◆ = reveal)</th>
                  <th scope="col" className="col-secondary">
                    Credentials
                  </th>
                  <th scope="col" className="col-secondary">
                    Last used
                  </th>
                  <th scope="col">Setup</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((sa) => {
                  const rows = credentialsFor(sa);
                  const scope = scopeFor(sa);
                  const open = expanded === sa.id;
                  const newest = showable(rows)
                    .map((c) => c.last_used_at)
                    .filter((at): at is string => at !== undefined)
                    .sort()
                    .at(-1);
                  return (
                    <ExpandableRow
                      key={sa.id}
                      account={sa}
                      scope={scope}
                      open={open}
                      scopeKnown={grantsQuery.isSuccess && environmentsQuery.isSuccess}
                      lastUsed={newest === undefined ? 'never' : isoDay(newest)}
                      onToggle={() => setExpanded(open ? null : sa.id)}
                    >
                      <ExpansionBody
                        account={sa}
                        scope={scope}
                        bearers={bearers(rows)}
                        bindings={bindings(rows)}
                        now={now}
                        ready={inputsReady}
                        onMint={(rotating) => setDialog({ kind: 'mint', account: sa, rotating })}
                        onBind={() => setDialog({ kind: 'binding', account: sa })}
                        onGrant={() => setDialog({ kind: 'grant', account: sa })}
                        onRevoke={(credential) => doRevoke(sa, credential)}
                      />
                    </ExpandableRow>
                  );
                })}
              </tbody>
            </table>
            {accounts.length === 0 && !accountsQuery.isPending && !accountsQuery.isError ? (
              <p role="status">No service accounts on this project yet.</p>
            ) : null}
            <p className="machine__footnote">
              The credential list is metadata only — prefix, kind, scope, expiry, last used. Values
              are write-only: displayed exactly once at mint, never retrievable, and rotation never
              returns the prior value.
            </p>
          </>
        ) : null}

        {tab === 'federation' ? (
          <>
            <h2>Federated bindings</h2>
            <p className="machine__lede">
              An external OIDC identity is bound to exactly one service account by a byte-exact
              (issuer, subject) pair — no wildcards, no case folding, no just-in-time provisioning.
              An unbound identity is not a login. A binding expires on the same terms as a bearer
              credential and is immutable: renewal is a mint.
            </p>
            {accounts.length > 0 ? (
              <p className="machine__actions">
                <button
                  className="btn btn--primary"
                  type="button"
                  disabled={!inputsReady}
                  onClick={() => {
                    const first = accounts[0];
                    if (first !== undefined) {
                      setDialog({ kind: 'binding', account: first });
                    }
                  }}
                >
                  New binding
                </button>
              </p>
            ) : null}
            {credentials.isPending || credentials.isError ? (
              <p role="status">
                {credentials.isError
                  ? 'The bindings could not be listed, so none are shown. This is not the same as there being none.'
                  : 'Reading bindings…'}
              </p>
            ) : allBindings.length === 0 ? (
              <p role="status">
                No federated bindings on this project. Add one from a service account&apos;s row.
              </p>
            ) : (
              <ul className="machine__bindings">
                {allBindings.map(({ account, credential }) => (
                  <li key={credential.id}>
                    <BindingCard account={account} credential={credential} now={now} />
                  </li>
                ))}
              </ul>
            )}
          </>
        ) : null}

        {tab === 'kubernetes' ? (
          <>
            <h2>Kubernetes delivery targets</h2>
            <p className="machine__lede">
              One managed Secret per delivery target, each reporting its state as a condition that
              reads the same in kubectl and here.
            </p>
            <p role="status">
              No delivery targets are reported. The Kubernetes operator that reconciles them and
              publishes their conditions is not part of this build, so this instance holds no target
              state to show — an empty list here means nothing is reporting, never that everything
              is healthy.
            </p>
          </>
        ) : null}
      </div>

      {dialog?.kind === 'mint' ? (
        <MintDialog
          project={project}
          account={dialog.account}
          rotating={dialog.rotating}
          reach={postStateReach(scopeFor(dialog.account))}
          onClose={() => setDialog(null)}
        />
      ) : null}

      {dialog?.kind === 'binding' ? (
        <BindingDialog
          project={project}
          accounts={accounts}
          initial={dialog.account}
          reachFor={(accountId) => {
            const sa = accounts.find((candidate) => candidate.id === accountId);
            return sa === undefined ? [] : postStateReach(scopeFor(sa));
          }}
          onClose={() => setDialog(null)}
          onCreated={(subject) => {
            setDialog(null);
            setNotice(`Bound. The binding matches ${subject} byte-for-byte and nothing else.`);
          }}
        />
      ) : null}

      {dialog?.kind === 'grant' ? (
        <GrantDialog
          project={project}
          account={dialog.account}
          scope={scopeFor(dialog.account)}
          // The SERVER's count, which applies the whole liveness predicate —
          // revocation, the credential epoch and expiry. Counting un-revoked
          // rows here would tell an operator that a grant re-scopes credentials
          // that stopped authenticating weeks ago.
          liveCredentials={dialog.account.live_credentials}
          onClose={() => setDialog(null)}
          onGranted={(environment) => {
            setDialog(null);
            setNotice(
              `Granted. Every credential this service account already holds now reads ${environment}.`,
            );
          }}
        />
      ) : null}
    </section>
  );
}

/**
 * PolicyStrip is the per-project machine-reveal opt-in, stated rather than
 * offered.
 *
 * A toggle here would be a control whose only outcome is a refusal: the opt-in
 * has no server surface, and the permission model's machine allowlist admits
 * `read` and nothing else on a workload principal until it lands. The repo's
 * own precedent is the ceremony's TOTP cap — absent with the reason given, not
 * disabled — and for the same reason: a greyed-out switch invites a support
 * ticket that a sentence answers.
 */
function PolicyStrip() {
  return (
    <p className="notice machine__policy" role="status">
      <span className="alert__glyph" aria-hidden="true">
        ◆
      </span>
      <span>
        <strong>Machine secret delivery (per-project opt-in): off in this build.</strong> Every
        workload delivery on this project is configuration and secret presence only. A credential
        holding reveal would be a standing decryption capability, so the acknowledgement that admits
        one is a deliberate per-project act — and it is not part of this build yet.
      </span>
    </p>
  );
}

function ExpandableRow({
  account,
  scope,
  open,
  scopeKnown,
  lastUsed,
  onToggle,
  children,
}: {
  account: ServiceAccount;
  scope: readonly MachineEnvScope[];
  open: boolean;
  /** False when the grants or the environments could not be read: unknown is not "none". */
  scopeKnown: boolean;
  lastUsed: string;
  onToggle: () => void;
  children: ReactNode;
}) {
  const reading = scope.filter((s) => s.read);
  const journey = setupJourney(account.kind, scope);
  const outstanding = journey?.findIndex((step) => step.state !== 'done') ?? -1;
  return (
    <>
      <tr>
        <th scope="row">
          <button
            className="values__keyname mono"
            type="button"
            aria-expanded={open}
            onClick={onToggle}
          >
            {`${open ? '▾' : '▸'} ${account.name}`}
          </button>
        </th>
        <td>
          <span className="badge">{account.kind}</span>
        </td>
        <td>
          {!scopeKnown ? (
            <span className="machine__none">unknown</span>
          ) : reading.length === 0 ? (
            <span className="machine__none">no environment</span>
          ) : (
            <span className="machine__chips">
              {reading.map((s) => (
                <span className="badge" key={s.id}>
                  {s.reveal ? `${s.name} ◆` : s.name}
                </span>
              ))}
            </span>
          )}
        </td>
        {/* The SERVER's live count: it applies revocation, the credential epoch
            and expiry, none of which a client filtering on `revoked_at` sees. */}
        <td className="col-secondary">{String(account.live_credentials)}</td>
        <td className="col-secondary">{lastUsed}</td>
        <td>
          <span className="badge">
            {journey === null
              ? 'not applicable'
              : !scopeKnown
                ? 'unknown'
                : outstanding === -1
                  ? 'complete'
                  : `step ${String(outstanding + 1)} of 5`}
          </span>
        </td>
      </tr>
      {open ? (
        <tr className="machine__sub">
          <td colSpan={6}>{children}</td>
        </tr>
      ) : null}
    </>
  );
}

function ExpansionBody({
  account,
  scope,
  bearers,
  bindings,
  now,
  ready,
  onMint,
  onBind,
  onGrant,
  onRevoke,
}: {
  account: ServiceAccount;
  scope: readonly MachineEnvScope[];
  bearers: readonly MachineCredential[];
  bindings: readonly MachineCredential[];
  now: Date;
  /** Every query this surface's warnings are computed from has succeeded. */
  ready: boolean;
  onMint: (rotating: boolean) => void;
  onBind: () => void;
  onGrant: () => void;
  onRevoke: (credential: MachineCredential) => void;
}) {
  const journey = setupJourney(account.kind, scope);
  return (
    <>
      <div className="machine__grid">
        <div>
          <h2 className="machine__subhead">Credentials</h2>
          {bearers.length === 0 ? (
            <p className="machine__none">
              No bearer credentials. This account authenticates by federation only, or not at all
              until one is minted.
            </p>
          ) : (
            <ul className="machine__creds">
              {bearers.map((credential) => (
                <li className="cred" key={credential.id}>
                  <code className="mono">{`${credential.prefix_hint ?? 'unknown'}…`}</code>
                  <span className="badge">bearer</span>
                  <span className="badge">{expiryLabel(credential, now)}</span>
                  <span className="cred__meta">{lastUsedLabel(credential)}</span>
                  <button
                    className="btn"
                    type="button"
                    disabled={!ready}
                    onClick={() => onMint(true)}
                  >
                    {`Rotate ${account.name}`}
                  </button>
                  <button className="btn" type="button" onClick={() => onRevoke(credential)}>
                    {`Revoke ${credential.prefix_hint ?? credential.id}`}
                  </button>
                </li>
              ))}
            </ul>
          )}

          {bindings.length > 0 ? (
            <>
              <h2 className="machine__subhead">Federated bindings</h2>
              <ul className="machine__bindings">
                {bindings.map((credential) => (
                  <li key={credential.id}>
                    <BindingCard account={account} credential={credential} now={now} />
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>

        <div>
          <h2 className="machine__subhead">Delivery targets</h2>
          <p role="status" className="machine__none">
            No Kubernetes delivery targets are reported for this account. The operator that publishes
            them is not part of this build.
          </p>
          {ready ? null : (
            <p className="machine__none" role="status">
              The actions are held back until the accounts, grants, environments and credentials
              have all been read: every one of their warnings is a statement about that state, and a
              query that failed would make it an understatement.
            </p>
          )}
          <div className="machine__actions">
            <button
              className="btn btn--primary"
              type="button"
              disabled={!ready}
              onClick={() => onMint(false)}
            >
              {`Mint credential for ${account.name}`}
            </button>
            <button className="btn" type="button" disabled={!ready} onClick={onBind}>
              {`Add federated binding to ${account.name}`}
            </button>
            <button className="btn" type="button" disabled={!ready} onClick={onGrant}>
              {`Add environment grant to ${account.name}`}
            </button>
          </div>
        </div>
      </div>

      <h2 className="machine__subhead">Setup journey</h2>
      {journey === null ? (
        <p className="machine__none">
          Automation principal — it runs off-box, on a schedule or in CI, and never delivers to a
          workload, so it has no setup journey. Its capability allowlist admits read, edit, publish
          and definitions-edit; never any manage- or instance capability.
        </p>
      ) : (
        <ol className="journey">
          {journey.map((step) => (
            <li className={`journey__step journey__step--${step.state}`} key={step.title}>
              <span className="journey__state">
                {step.state === 'done'
                  ? 'done'
                  : step.state === 'next'
                    ? 'next'
                    : 'not in this build'}
              </span>
              <span className="journey__body">
                <span className="journey__title">{step.title}</span>
                <span className="journey__note">{step.note}</span>
              </span>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}

function BindingCard({
  account,
  credential,
  now,
}: {
  account: ServiceAccount;
  credential: MachineCredential;
  now: Date;
}) {
  return (
    <div className="bindrow">
      <p className="bindrow__head">
        <code className="mono">{account.name}</code>
        <span className="badge">federated</span>
        <span className="badge">{expiryLabel(credential, now)}</span>
        <span className="cred__meta">
          matched byte-for-byte — no wildcards, no case folding; renewal is a mint
        </span>
      </p>
      {/* Every pair is wrapped: a `dl` takes either dt/dd children or `div`
          children, never a mixture, and axe checks exactly that. */}
      <dl className="kv">
        {[
          { term: 'issuer', value: credential.issuer ?? 'unknown' },
          { term: 'subject', value: credential.subject ?? 'unknown' },
          { term: 'audience', value: credential.audience ?? 'unknown' },
          ...(credential.required_claims ?? []).map((pin) => ({
            term: pin.claim,
            value: claimText(pin),
          })),
        ].map((pair) => (
          <div className="kv__pair" key={pair.term}>
            <dt>{pair.term}</dt>
            <dd className="mono">{pair.value}</dd>
          </div>
        ))}
      </dl>
      {credential.reactivated_at === undefined ? null : (
        <p className="notice" role="status">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            {`Quarantined since the restore on ${isoDay(credential.reactivated_at)}: this binding permanently refuses any token issued at or before that instant plus the accepted clock skew.`}
          </span>
        </p>
      )}
    </div>
  );
}

function claimText(pin: ClaimPin): string {
  if (pin.string_value !== undefined) {
    return pin.string_value;
  }
  if (pin.number_value !== undefined) {
    return String(pin.number_value);
  }
  if (pin.bool_value !== undefined) {
    return String(pin.bool_value);
  }
  return 'unpinned';
}

/**
 * useModalDialog opens a native `<dialog>` with `showModal()`.
 *
 * The platform gives a real focus trap, an inert document behind it, Escape and
 * the top layer — every part of which a hand-rolled `role="dialog"` has to
 * reimplement, and the focus trap is the part everyone gets wrong.
 */
function useModalDialog() {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = ref.current;
    if (element !== null && !element.open) {
      element.showModal();
    }
  }, []);
  return ref;
}

/**
 * useNavigationGuard keeps navigation from destroying what dismissal is not
 * allowed to.
 *
 * `dismissDecision` gates Escape and the buttons, but the browser has two more
 * ways to unmount this dialog: unload (reload, tab close, external navigation)
 * and the Back button, which pops the route out from under the component. The
 * first gets the platform's `beforeunload` confirmation; the second gets a
 * history sentinel — a duplicate entry pushed while the guard is active, so a
 * Back press consumes the sentinel instead of the route, the URL never changes,
 * and the press is surfaced as a dismissal ATTEMPT routed through the same
 * gate as Escape. Deactivating consumes the sentinel again so Back is not a
 * double-press afterwards.
 */
function useNavigationGuard(active: boolean, onAttempt: () => void) {
  const attempt = useRef(onAttempt);
  attempt.current = onAttempt;
  useEffect(() => {
    if (!active) {
      return;
    }
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    const onPopState = () => {
      history.pushState(null, '', window.location.href);
      attempt.current();
    };
    history.pushState(null, '', window.location.href);
    window.addEventListener('beforeunload', onBeforeUnload);
    window.addEventListener('popstate', onPopState);
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
      window.removeEventListener('popstate', onPopState);
      history.back();
    };
  }, [active]);
}

/**
 * MintDialog is the display-once ceremony, and it is the only component in the
 * SPA that ever holds a credential value.
 *
 * The step-up names the POST-STATE formula rather than what the mint adds: a
 * mint adds no grants, so a replacement credential is not a smaller act than a
 * new one — it hands the same reach to a fresh value. When the account reaches
 * no plaintext the disclosure conjunct is vacuous and the server asks for no
 * reauthentication, which the panel says in words rather than performing a
 * ceremony that authorises nothing.
 */
function MintDialog({
  project,
  account,
  rotating,
  reach,
  onClose,
}: {
  project: ProjectRef;
  account: ServiceAccount;
  rotating: boolean;
  reach: readonly MachineEnvScope[];
  onClose: () => void;
}) {
  const dialog = useModalDialog();
  const refresh = useRefreshAccount(project);
  const [value, setValue] = useState<string | null>(null);
  const [clamped, setClamped] = useState(false);
  const [stored, setStored] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [heldBack, setHeldBack] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const confirmation = useRef<HTMLInputElement>(null);

  // The panel the value arrives on replaces the control that was focused, so
  // focus goes to the one decision left: the stored-confirmation checkbox.
  useEffect(() => {
    if (value !== null) {
      confirmation.current?.focus();
    }
  }, [value]);

  const run = async () => {
    setBusy(true);
    setFailure(null);
    // `issued` is the difference between "nothing happened" and "something may
    // have". Once the request leaves, a failure says nothing about whether the
    // server committed — and a mint that committed and whose response was lost
    // is a live credential whose value is gone forever.
    let issued = false;
    try {
      // One reauthentication per environment the account reaches in the
      // post-state, which is exactly the set the server will consume. An empty
      // reach runs no ceremony because there is no disclosure to authorise.
      for (const environment of reach) {
        await runPasskeyCeremony({
          operation: 'mint',
          environmentId: environment.id,
          keyIds: [],
        });
      }
      issued = true;
      const minted = await mintCredential(project, account.id);
      setValue(minted.value);
      setClamped(minted.clamped);
      refresh(account.id);
    } catch (error) {
      if (issued) {
        // Re-read the rows so the operator can see — and revoke — whatever may
        // have landed.
        refresh(account.id);
        setFailure(mintFailureText(error));
      } else {
        setFailure(identityRefusalText(error));
      }
    } finally {
      setBusy(false);
    }
  };

  const dismiss = () => {
    switch (dismissDecision({ busy, hasValue: value !== null, stored })) {
      case 'ignore':
        return;
      case 'hold-back':
        setHeldBack(true);
        return;
      default:
        onClose();
    }
  };

  // Back, reload and tab close are dismissals too — an in-flight mint or an
  // unstored value must not be lost to a navigation the buttons would refuse.
  useNavigationGuard(busy || (value !== null && !stored), dismiss);

  return (
    <dialog
      className="ceremony"
      aria-labelledby="mint-title"
      ref={dialog}
      onCancel={(event) => {
        // Escape must not be a way to lose a value nothing can return.
        event.preventDefault();
        dismiss();
      }}
    >
      {value === null ? (
        <>
          <h2 className="ceremony__title" id="mint-title">
            {`${rotating ? 'rotate' : 'mint'} credential · ${account.name}`}
          </h2>
          <p className="ceremony__stepup">
            <span className="alert__glyph" aria-hidden="true">
              ⚿
            </span>
            <span>
              <strong>Confirm it&apos;s you.</strong> The value is delivered display-once, to you.
              The formula is manage-identities on this project and a disclosure capability over
              every environment this account reaches in the resulting post-state — not only the ones
              a mint adds, because a mint adds none.
            </span>
          </p>
          <p className="ceremony__scope">
            {reach.length === 0
              ? 'This account reaches no plaintext in the resulting post-state, so no disclosure capability and no reauthentication are required. Its deliveries stay configuration and secret presence only.'
              : `This account decrypts ${reach.map((r) => r.name).join(', ')}. Each takes its own passkey reauthentication before the value is minted.`}
          </p>
          {rotating ? (
            <p className="ceremony__lede">
              The prior value is never returned. The predecessor keeps authenticating until you
              revoke it — rotation and revocation are separate, deliberate acts, so a mint that
              lands and a revoke that does not leaves two live credentials rather than none.
            </p>
          ) : null}
          {failure !== null ? (
            <p className="alert" role="alert">
              <span className="alert__glyph" aria-hidden="true">
                !
              </span>
              <span>{failure}</span>
            </p>
          ) : null}
          <div className="ceremony__actions">
            <button
              className="btn btn--primary"
              type="button"
              disabled={busy}
              onClick={() => void run()}
            >
              {busy
                ? 'Minting…'
                : reach.length === 0
                  ? 'Mint credential'
                  : 'Use a passkey and mint'}
            </button>
            <button className="btn" type="button" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          </div>
        </>
      ) : (
        <>
          <h2 className="ceremony__title" id="mint-title">
            Credential minted — shown exactly once
          </h2>
          <p className="mono machine__token">{value}</p>
          {clamped ? (
            <p className="notice" role="status">
              <span className="alert__glyph" aria-hidden="true">
                !
              </span>
              <span>
                The instance lifetime ceiling shortened this credential. It expires earlier than the
                default asked for — said now rather than discovered when it dies.
              </span>
            </p>
          ) : null}
          <p className="ceremony__cap" role="status">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>
              This value is never retrievable again. The list shows metadata only and rotation never
              returns it. Store it in the consuming system now; if it is lost, revoke this
              credential and mint a fresh one.
            </span>
          </p>
          <button
            className="btn"
            type="button"
            onClick={() => {
              void navigator.clipboard
                .writeText(value)
                .then(() =>
                  setCopied(
                    'Copied. The clipboard is now the only copy outside its target system.',
                  ),
                )
                .catch(() => setCopied('This browser refused clipboard access, so nothing was copied.'));
            }}
          >
            Copy to clipboard
          </button>
          {copied === null ? null : (
            <p className="notice" role="status">
              <span className="alert__glyph" aria-hidden="true">
                ⧉
              </span>
              <span>{copied}</span>
            </p>
          )}
          <div className="field chk">
            <input
              id="mint-stored"
              type="checkbox"
              ref={confirmation}
              checked={stored}
              onChange={(event) => {
                setStored(event.target.checked);
                setHeldBack(false);
              }}
            />
            <label htmlFor="mint-stored">I have stored this credential in its target system.</label>
          </div>
          {heldBack ? (
            <p className="alert" role="alert">
              <span className="alert__glyph" aria-hidden="true">
                !
              </span>
              <span>Confirm you have stored it — there is no second look at this value.</span>
            </p>
          ) : null}
          <div className="ceremony__actions">
            <button className="btn btn--primary" type="button" onClick={dismiss}>
              Done
            </button>
          </div>
        </>
      )}
    </dialog>
  );
}

/**
 * BindingDialog is the federation form.
 *
 * Two of its rules come straight off the server and are asked for HERE so an
 * operator meets them as a form rather than as a 400: the audience is mandatory
 * and may not be the issuer's default, and each platform's immutable
 * identifiers must be pinned. The third — the pull-request refusal — is the
 * load-bearing one: the protection comes from the pinned `event_name`, never
 * from the subject's shape, because a `pull_request_target` token carries the
 * ordinary ref-form subject a production binding names.
 */
function BindingDialog({
  project,
  accounts,
  initial,
  reachFor,
  onClose,
  onCreated,
}: {
  project: ProjectRef;
  accounts: readonly ServiceAccount[];
  initial: ServiceAccount;
  /**
   * The selected account's post-state reach. A binding is a mint (#62), so the
   * server demands the same disclosure formula the credential mint does: one
   * fresh window per environment the account can decrypt in the resulting
   * state. Vacuous today for the same reason the mint's is — nothing a machine
   * can hold reaches plaintext — but the leg exists so the form does not start
   * failing with a bare 403 the day the reveal opt-in lands.
   */
  reachFor: (accountId: string) => readonly MachineEnvScope[];
  onClose: () => void;
  onCreated: (subject: string) => void;
}) {
  const dialog = useModalDialog();
  const create = useCreateBinding(project);
  const refresh = useRefreshAccount(project);
  const [account, setAccount] = useState(initial.id);
  const [preset, setPreset] = useState<FederationPreset>(KUBERNETES_PRESET);
  const [issuer, setIssuer] = useState(KUBERNETES_PRESET.issuer);
  const [subject, setSubject] = useState(KUBERNETES_PRESET.subject);
  const [audience, setAudience] = useState('');
  const [claims, setClaims] = useState<Record<string, string>>(() => blankClaims(KUBERNETES_PRESET));
  const [lifetime, setLifetime] = useState('default');
  const [deliberate, setDeliberate] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // A refusal describes the form as it was when it was refused. Editing any
  // field makes it stale, and a stale refusal sitting beside a fresh one is two
  // alerts saying different things about one form.
  const edited = () => setFailure(null);

  const choose = (next: FederationPreset) => {
    setPreset(next);
    setIssuer(next.issuer);
    setSubject(next.subject);
    setClaims(blankClaims(next));
    setDeliberate(false);
    edited();
  };

  const eventName = claims['event_name'] ?? '';
  const refusal = pullRequestRefusal(eventName);

  /**
   * pinsOrRefusal builds the pinned claims, or names the first field that
   * cannot be one.
   *
   * The numeric fields are the ones worth refusing over: an immutable
   * repository id is what stops a renamed-and-reused path inheriting this
   * binding, and a field that quietly became 0 — or rounded to a neighbouring
   * id past 2^53 — would bind this service account to somebody else's
   * repository while looking like it worked.
   */
  const pinsOrRefusal = (): FederatedClaimPin[] | string => {
    const pins: FederatedClaimPin[] = [];
    for (const field of preset.claims) {
      const raw = claims[field.claim] ?? '';
      if (field.kind === 'number') {
        const value = parseClaimNumber(raw);
        if (value === null) {
          return `${field.label} (${field.claim}) must be a whole number the issuer actually mints — digits only, and inside the range this contract can carry exactly. Nothing was bound.`;
        }
        pins.push({ claim: field.claim, number_value: value });
        continue;
      }
      if (raw.trim() === '') {
        return `${field.label} (${field.claim}) is required: this issuer's bindings must pin it, and the server refuses a binding without it. Nothing was bound.`;
      }
      pins.push({ claim: field.claim, string_value: raw });
    }
    return pins;
  };

  const submit = async () => {
    if (refusal !== null && !deliberate) {
      setFailure(
        'This binding pins a pull-request event. Acknowledge deliberately below, or pin another event.',
      );
      return;
    }
    // Mandatory, and refused HERE rather than as a 400: a token minted for
    // another consumer must not authenticate here, and an empty field is the
    // most likely way to end up with no such constraint at all.
    if (audience.trim() === '') {
      setFailure(
        'An audience is mandatory, and it may never be the issuer’s default. A token minted for another consumer must not authenticate here. Nothing was bound.',
      );
      return;
    }
    const pins = pinsOrRefusal();
    if (typeof pins === 'string') {
      setFailure(pins);
      return;
    }
    setBusy(true);
    setFailure(null);
    // Same issued-vs-nothing-happened line the mint draws: once the request
    // leaves, a failure says nothing about whether a live external login path
    // now exists, and the row list is the only place it would show.
    let issued = false;
    try {
      // A binding is a mint: one reauthentication per environment the account
      // decrypts in the post-state, in the same purpose the server consumes.
      // Empty today — no machine reaches plaintext — so no ceremony runs.
      for (const environment of reachFor(account)) {
        await runPasskeyCeremony({
          operation: 'mint',
          environmentId: environment.id,
          keyIds: [],
        });
      }
      const seconds = BINDING_LIFETIMES.find((entry) => entry.id === lifetime)?.seconds;
      issued = true;
      await create.mutateAsync({
        serviceAccount: account,
        issuer,
        subject,
        audience,
        requiredClaims: pins,
        ...(seconds === undefined ? {} : { lifetimeSeconds: seconds }),
      });
      onCreated(subject);
    } catch (error) {
      if (issued) {
        refresh(account);
        setFailure(bindingFailureText(error));
      } else {
        setFailure(identityRefusalText(error));
      }
    } finally {
      setBusy(false);
    }
  };

  // An in-flight binding is not dismissible: Escape, Back or unload here would
  // hide a mutation that may commit — the operator stays until it resolves.
  useNavigationGuard(busy, () => {});

  return (
    <dialog className="ceremony" aria-labelledby="binding-title" ref={dialog} onCancel={(e) => {
      e.preventDefault();
      if (!busy) {
        onClose();
      }
    }}>
      <h2 className="ceremony__title" id="binding-title">
        Add federated binding
      </h2>
      <p className="ceremony__lede">
        A byte-exact (issuer, subject) pair naming exactly one service account. The audience is
        mandatory and may not be the issuer&apos;s default: a token minted for another consumer must
        not authenticate here.
      </p>

      {/* One native latch for the whole target: an issued request is for the
          form as submitted, so nothing here may change until it resolves —
          otherwise the success or failure sentence describes one account while
          the operator is looking at another. */}
      <fieldset className="machine__lock" disabled={busy}>
      <div className="machine__presets">
        {FEDERATION_PRESETS.map((entry) => (
          <button
            key={entry.id}
            className="btn"
            type="button"
            aria-pressed={preset.id === entry.id}
            onClick={() => choose(entry)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="field">
        <label htmlFor="binding-account">Service account</label>
        <select
          id="binding-account"
          value={account}
          onChange={(event) => {
            // The acknowledgement is consent for ONE account's fetch authority.
            // A different target is a different decision, so it does not carry.
            setAccount(event.target.value);
            setDeliberate(false);
            edited();
          }}
        >
          {accounts.map((sa) => (
            <option key={sa.id} value={sa.id}>
              {sa.name}
            </option>
          ))}
        </select>
      </div>

      <div className="field">
        <label htmlFor="binding-issuer">Issuer</label>
        <input
          id="binding-issuer"
          className="mono"
          value={issuer}
          onChange={(event) => {
            setIssuer(event.target.value);
            edited();
          }}
        />
      </div>

      <div className="field">
        <label htmlFor="binding-subject">Subject, matched byte-for-byte</label>
        <input
          id="binding-subject"
          className="mono"
          value={subject}
          onChange={(event) => {
            setSubject(event.target.value);
            edited();
          }}
        />
      </div>

      <div className="field">
        <label htmlFor="binding-audience">Audience</label>
        <input
          id="binding-audience"
          className="mono"
          value={audience}
          onChange={(event) => {
            setAudience(event.target.value);
            edited();
          }}
        />
      </div>

      {preset.claims.map((field) =>
        field.kind === 'event' ? (
          <div className="field" key={field.claim}>
            <label htmlFor="binding-event">{field.label}</label>
            <select
              id="binding-event"
              value={eventName}
              onChange={(event) => {
                setClaims((current) => ({ ...current, event_name: event.target.value }));
                setDeliberate(false);
                edited();
              }}
            >
              {CI_EVENTS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div className="field" key={field.claim}>
            <label htmlFor={presetFieldId(field.claim)}>{`${field.label} (${field.claim})`}</label>
            <input
              id={presetFieldId(field.claim)}
              className="mono"
              inputMode={field.kind === 'number' ? 'numeric' : 'text'}
              value={claims[field.claim] ?? ''}
              onChange={(event) => {
                setClaims((current) => ({ ...current, [field.claim]: event.target.value }));
                edited();
              }}
            />
          </div>
        ),
      )}

      <div className="field">
        <label htmlFor="binding-lifetime">Binding lifetime</label>
        <select
          id="binding-lifetime"
          value={lifetime}
          onChange={(event) => {
            setLifetime(event.target.value);
            edited();
          }}
        >
          {BINDING_LIFETIMES.map((entry) => (
            <option key={entry.id} value={entry.id} disabled={entry.disabled === true}>
              {entry.label}
            </option>
          ))}
        </select>
      </div>

      {refusal === null ? null : (
        <>
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>{refusal}</span>
          </p>
          <div className="field chk">
            <input
              id="binding-deliberate"
              type="checkbox"
              checked={deliberate}
              onChange={(event) => setDeliberate(event.target.checked)}
            />
            <label htmlFor="binding-deliberate">
              I am deliberately binding a pull-request identity and accept that pull-request authors
              reach this account&apos;s scope.
            </label>
          </div>
        </>
      )}
      </fieldset>

      {failure !== null ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      ) : null}

      <p className="machine__footnote">
        No wildcards, no namespace patterns, no case folding — canonicalisation merges distinct
        external identities. Bindings are immutable and expire on the same terms as a bearer
        credential: renewal is a mint, never an edit.
      </p>

      <div className="ceremony__actions">
        <button className="btn btn--primary" type="button" disabled={busy} onClick={() => void submit()}>
          {busy ? 'Binding…' : 'Bind this identity'}
        </button>
        <button className="btn" type="button" onClick={onClose} disabled={busy}>
          Cancel
        </button>
      </div>
    </dialog>
  );
}

/**
 * GrantDialog is the grant-mutation warning.
 *
 * A grant attaches to the SERVICE ACCOUNT, never to a credential, so it
 * re-scopes every credential already in circulation the moment it lands. The
 * warning therefore names two numbers the operator cannot see anywhere else:
 * how many live credentials that is, and exactly which keys become reachable.
 *
 * Only `read` is offered, and that is the permission model rather than a
 * simplification: a workload principal's allowlist admits `read` and nothing
 * else, so a `reveal` control here would be refused every time it was pressed.
 */
function GrantDialog({
  project,
  account,
  scope,
  liveCredentials,
  onClose,
  onGranted,
}: {
  project: ProjectRef;
  account: ServiceAccount;
  scope: readonly MachineEnvScope[];
  liveCredentials: number;
  onClose: () => void;
  onGranted: (environment: string) => void;
}) {
  const dialog = useModalDialog();
  const grantable = scope.filter((s) => !s.read);
  // The in-flight latch lives here because the <dialog>'s cancel event does,
  // while the mutation lives in GrantBody — a ref, because the gate needs the
  // truth at event time, not a render.
  const inFlight = useRef(false);

  return (
    <dialog className="ceremony" aria-labelledby="grant-title" ref={dialog} onCancel={(e) => {
      e.preventDefault();
      if (!inFlight.current) {
        onClose();
      }
    }}>
      <h2 className="ceremony__title" id="grant-title">
        {`Add environment grant · ${account.name}`}
      </h2>
      <p className="ceremony__lede">
        Grants attach to the service account, never to a credential.
      </p>

      {grantable.length === 0 ? (
        <p role="status">
          This account already reads every environment in the project. There is nothing to widen.
        </p>
      ) : (
        <GrantBody
          project={project}
          account={account}
          scope={scope}
          grantable={grantable}
          liveCredentials={liveCredentials}
          inFlight={inFlight}
          onClose={onClose}
          onGranted={onGranted}
        />
      )}
    </dialog>
  );
}

/**
 * GrantBody exists so its queries and selection state are never mounted when
 * there is nothing grantable. Hooks cannot be conditional, and a query fired
 * for a dialog that only says "nothing to widen" would be a request the
 * surface makes and then ignores.
 */
function GrantBody({
  project,
  account,
  scope,
  grantable,
  liveCredentials,
  inFlight,
  onClose,
  onGranted,
}: {
  project: ProjectRef;
  account: ServiceAccount;
  scope: readonly MachineEnvScope[];
  grantable: readonly MachineEnvScope[];
  liveCredentials: number;
  /** GrantDialog's Escape gate — held while the mutation is in flight. */
  inFlight: MutableRefObject<boolean>;
  onClose: () => void;
  onGranted: (environment: string) => void;
}) {
  const grant = useGrantEnvironment(project);
  const refreshGrants = useRefreshGrants(project);
  const first = grantable[0];
  const [environment, setEnvironment] = useState(first === undefined ? '' : first.id);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // An in-flight grant is not dismissible by Back or unload either: a widening
  // that commits behind a dismissed dialog is invisible at the moment it most
  // needs review.
  useNavigationGuard(busy, () => {});

  /**
   * What a `read` grant actually delivers, read off the delivery surface rather
   * than guessed: the whole key CATALOGUE — every key's name and its
   * classification — and no value of any classification, config included. So
   * the newly reachable set is every key, not only the secrets. The catalogue
   * endpoint is used rather than the value listing on purpose: a value listing
   * is authorized for the HUMAN reading it and carries config plaintext this
   * dialog never renders, and a fetch is a cached copy (see useKeyCatalogue).
   */
  const values = useKeyCatalogue(project);
  const reachable = values.data?.items ?? [];
  const chosen = grantable.find((s) => s.id === environment);
  // The mint formula's conjunct for a WIDENING is the delta, not the whole
  // post-state — which is what the server computes in checkMachineWidening.
  const widening = grantWideningReach(scope, environment, 'read');

  const submit = async () => {
    setBusy(true);
    inFlight.current = true;
    setFailure(null);
    // Issued-vs-nothing-happened, the mint's line: once the request leaves, a
    // failure does not mean the widening did not land — and a widening that
    // landed re-scoped every live credential the moment it did.
    let issued = false;
    try {
      // Each newly reachable environment takes its own reauthentication, in the
      // same purpose the server consumes. Empty today, and for the same reason
      // the mint's is: nothing this account can hold reaches plaintext.
      for (const widened of widening) {
        await runPasskeyCeremony({
          operation: 'mint',
          environmentId: widened.id,
          keyIds: [],
        });
      }
      issued = true;
      await grant.mutateAsync({
        environment,
        principal: account.principal_id,
        capability: 'read',
      });
      onGranted(chosen?.name ?? environment);
    } catch (error) {
      if (issued) {
        refreshGrants();
        setFailure(grantFailureText(error));
      } else {
        setFailure(identityRefusalText(error));
      }
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return (
    <>
      <div className="field">
        <label htmlFor="grant-environment">Environment (read)</label>
        <select
          id="grant-environment"
          value={environment}
          onChange={(event) => setEnvironment(event.target.value)}
        >
          {grantable.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
      </div>

      <p className="ceremony__cap" role="status">
        <span className="alert__glyph" aria-hidden="true">
          !
        </span>
        <span>
          {`This grant re-scopes every credential already in circulation. ${account.name} has ${String(liveCredentials)} live credential${liveCredentials === 1 ? '' : 's'}, and each one gains read — configuration and secret presence — on ${chosen?.name ?? 'that environment'} the moment this lands.`}
        </span>
      </p>

      <p className="ceremony__stepup">
        <span className="alert__glyph" aria-hidden="true">
          ⚿
        </span>
        <span>
          <strong>The formula.</strong> manage-identities on this project, manage-members over the
          environment, and a disclosure capability over every environment this grant NEWLY lets the
          account decrypt — the delta, not the whole post-state, because that is what the grant
          adds.{' '}
          {widening.length === 0
            ? 'This grant newly decrypts nothing, so the disclosure conjunct is vacuous and no reauthentication is required.'
            : `It newly decrypts ${widening.map((w) => w.name).join(', ')}, so each takes its own passkey reauthentication before the grant lands.`}
        </span>
      </p>

      {/* FAIL CLOSED. A pending or failed catalogue read cannot be rendered as
          "nothing becomes reachable": that is the one answer it does not have,
          and it is the answer that makes the grant look harmless. */}
      {values.isSuccess ? (
        <>
          <p className="ceremony__scope">
            {reachable.length === 0
              ? 'This project declares no keys, so the grant reaches an empty catalogue today — and every key declared later.'
              : 'Newly reachable: every key below, by name and classification. No value of any classification is delivered to a machine by this build.'}
          </p>
          {reachable.length === 0 ? null : (
            <ul className="ceremony__keys" aria-label="Keys this grant makes reachable">
              {reachable.map((key) => (
                <li className="mono" key={key.id}>
                  {`${key.name} · ${key.classification}`}
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            {values.isError
              ? 'The key catalogue could not be read, so what this grant makes reachable cannot be named — and a grant whose blast radius is unknown is not one to make from here.'
              : 'Reading what this grant would make reachable…'}
          </span>
        </p>
      )}

      {failure !== null ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      ) : null}

      <div className="ceremony__actions">
        <button
          className="btn btn--primary"
          type="button"
          disabled={busy || environment === '' || !values.isSuccess}
          onClick={() => void submit()}
        >
          {busy ? 'Granting…' : 'Grant read'}
        </button>
        <button className="btn" type="button" onClick={onClose} disabled={busy}>
          Cancel
        </button>
      </div>
    </>
  );
}

/** blankClaims is a preset's pin fields, empty except the event a CI binding defaults to. */
function blankClaims(preset: FederationPreset): Record<string, string> {
  return Object.fromEntries(
    preset.claims.map((field) => [field.claim, field.kind === 'event' ? 'push' : '']),
  );
}
