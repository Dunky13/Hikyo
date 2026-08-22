import qrcode from 'qrcode-generator';
import { useId, useMemo, useState } from 'react';

import {
  accountFailureText,
  useAuthMethods,
  useConfirmTotp,
  useEnrolPasskey,
  useEnrolTotpStart,
  useIdentities,
  useLinkIdentity,
  usePasskeys,
  useRegenerateRecoveryCodes,
  useRemovePasskey,
  useRemoveTotp,
  useTotpStatus,
  useUnlinkIdentity,
} from '../api/account.ts';
import { useRevokeSession, useSessions, type ActiveSession } from '../api/remotes.ts';
import { useSession } from '../api/session.ts';
import { themeLabel, useThemeChoice, type ThemeChoice } from '../app/theme.ts';
import { clearNotification, notifyFailure } from '../app/notifications.tsx';
import { Alert, Done, JumpIndex, Panel } from './Sections.tsx';
import { useFeedback, useModalDialog } from './useModalDialog.ts';

/**
 * Account & security (registry surface `settings`, #60; locked prototype
 * app-chrome iteration 15, sections Profile · Sign-in factors · Recovery ·
 * Active sessions · Linked identities · Preferences).
 *
 * This surface absorbed what #71 shipped as a standalone session list: the
 * kill switch is one panel of the account, not a page of its own, which is
 * where a human looks for it.
 *
 * Every mutation on this page is an account-security mutation, and they share
 * one rule the prototype drew as a blue "confirm it's you" step-up: the proof
 * is the PRE-EXISTING credential — the password, or a confirmed code — never
 * the credential being added or removed. One dialog asks for it, so the rule
 * is stated once and cannot be half-applied.
 *
 * Deliberately absent, each for a stated reason:
 *
 *  - **Editing the profile.** There is no operation that writes a display name
 *    or an email anywhere in the contract; the fields are shown as what they
 *    are, read-only facts about the signed-in principal.
 *  - **Passkey-only sign-in.** The prototype's toggle has no backing state or
 *    operation; the passwordless floor is enforced server-side at removal
 *    time, and a switch that only pretended to set a policy is worse than
 *    none.
 *  - **Notification preferences.** No operation, and the ADR's own answer is
 *    that security alerts are not disableable — so there is nothing to offer.
 */
export function AccountSecurity() {
  const session = useSession();
  const passkeys = usePasskeys();
  const totpStatus = useTotpStatus();
  const identities = useIdentities();
  const methods = useAuthMethods();
  const sessions = useSessions();
  const revokeSession = useRevokeSession();

  const enrolPasskey = useEnrolPasskey();
  const removePasskey = useRemovePasskey();
  const totpStart = useEnrolTotpStart();
  const totpConfirm = useConfirmTotp();
  const totpRemove = useRemoveTotp();
  const regenerate = useRegenerateRecoveryCodes();
  const unlink = useUnlinkIdentity();
  const link = useLinkIdentity();

  const [proof, setProof] = useState<ProofRequest | null>(null);
  const { done, report: recordFailure, ok: recordSuccess } = useFeedback(accountFailureText);
  const report = (error: unknown) => {
    notifyFailure(accountFailureText(error));
    recordFailure(error);
  };
  const ok = (message: string) => {
    clearNotification();
    recordSuccess(message);
  };
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [codes, setCodes] = useState<readonly string[] | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const codeId = useId();

  // The locally-held seed is SPENT once the server no longer has a matching
  // mid-flight enrolment: a settled status that reports a confirmed factor
  // (done) or, with nothing pending, no factor at all (the window lapsed). The
  // `!isFetching` guard scopes the "no factor" case to a SETTLED read, so the
  // refetch a fresh start kicks off — which resolves to pending — does not count
  // the still-cached previous value as spent.
  const totpSeedSpent =
    totpStatus.isSuccess &&
    (totpStatus.data.confirmed || (!totpStatus.isFetching && !totpStatus.data.pending));

  // A real enrolment is in progress exactly while we hold an unspent seed. The
  // ceremony and the status line both read THIS rather than the query, so
  // neither flashes the lagging cached status during the post-start refetch.
  const totpEnrolmentInProgress = otpauth !== null && !totpSeedSpent;

  const runProof = (value: string) => {
    const request = proof;
    if (request === null) {
      return;
    }
    setProof(null);
    switch (request.kind) {
      case 'add-passkey':
        enrolPasskey.mutate(
          { password: value },
          {
            onSuccess: () => ok('Passkey enrolled. Every other session you held has ended.'),
            onError: report,
          },
        );
        return;
      case 'remove-passkey':
        removePasskey.mutate(
          { id: request.id, password: value },
          { onSuccess: () => ok('Passkey removed.'), onError: report },
        );
        return;
      case 'totp-start':
        totpStart.mutate(
          { password: value },
          {
            onSuccess: (result) => {
              setOtpauth(result.otpauth_uri);
              ok('Enrolment started. The secret below is shown exactly once.');
            },
            onError: report,
          },
        );
        return;
      case 'totp-remove':
        totpRemove.mutate(
          { password: value },
          { onSuccess: () => ok('Authenticator factor removed.'), onError: report },
        );
        return;
      case 'recovery':
        regenerate.mutate(
          { proof: value },
          {
            onSuccess: (result) => {
              setCodes(result.recovery_codes);
              ok('A new batch replaced the old one. The codes are shown exactly once.');
            },
            onError: report,
          },
        );
        return;
      case 'unlink':
        unlink.mutate(
          { id: request.id, password: value },
          { onSuccess: () => ok('Identity unlinked.'), onError: report },
        );
        return;
      case 'link':
        link.mutate(
          { provider: request.provider, kind: request.providerKind, proof: value },
          {
            onSuccess: (redirect) => window.location.assign(redirect),
            onError: report,
          },
        );
        return;
    }
  };

  const principal = session.data?.principal;
  const assurance = session.data?.session.assurance;

  return (
    <div className="page">
      <h1>Account &amp; security</h1>
      <p className="page__lede">
        Security changes ask for the credential you already have — your password, or a code from an
        authenticator you already enrolled. That is deliberately not the teal disclosure ceremony: a
        step-up proves who you are, a reveal ceremony authorises one disclosure.
      </p>

      <JumpIndex
        sections={[
          { id: 'account-profile', label: 'Profile' },
          { id: 'account-factors', label: 'Sign-in factors' },
          { id: 'account-recovery', label: 'Recovery' },
          { id: 'account-sessions', label: 'Active sessions' },
          { id: 'account-identities', label: 'Linked identities' },
          { id: 'account-preferences', label: 'Preferences' },
        ]}
      />

      {done !== null ? <Done>{done}</Done> : null}

      <Panel id="account-profile" title="Profile">
        <dl className="kv">
          <div className="kv__pair">
            <dt>Principal</dt>
            <dd className="mono">{principal === undefined ? 'Unavailable' : principal.id}</dd>
          </div>
          <div className="kv__pair">
            <dt>Display name</dt>
            <dd>
              {principal === undefined
                ? 'Unavailable'
                : principal.display_name === null || principal.display_name === undefined
                  ? 'Not set'
                  : principal.display_name}
            </dd>
          </div>
          <div className="kv__pair">
            <dt>This session authenticated with</dt>
            <dd>{assurance === undefined ? '—' : assurance.factors.join(', ')}</dd>
          </div>
        </dl>
        <p className="field__hint">
          Read-only: nothing in this version writes a profile. A display name is display only and is
          never a linking key, for any provider, at any point. There is no self-service password
          change either: a lost or compromised password is re-established through a reset an
          administrator issues for your account.
        </p>
      </Panel>

      <Panel id="account-factors" title="Sign-in factors">
        <h3>Passkeys</h3>
        {passkeys.isPending ? <p role="status">Loading passkeys…</p> : null}
        {passkeys.isError ? <Alert>Your passkeys could not be listed.</Alert> : null}
        {passkeys.isSuccess && passkeys.data.passkeys.length === 0 ? (
          <p role="status">No passkey is enrolled on this account.</p>
        ) : null}
        <ul className="factors">
          {passkeys.isSuccess ? passkeys.data.passkeys.map((passkey) => (
            <li className="factor" key={passkey.id}>
              <div>
                <strong>{passkey.label}</strong>
                <span className="factor__meta">
                  added {new Date(passkey.created_at).toLocaleDateString()} · last used{' '}
                  {new Date(passkey.last_used_at).toLocaleDateString()}
                  {passkey.disabled ? ' · disabled after a clone signal' : ''}
                </span>
              </div>
              <button
                type="button"
                className="btn"
                aria-label={`Remove passkey ${passkey.label}`}
                onClick={() => setProof({ kind: 'remove-passkey', id: passkey.id })}
              >
                Remove
              </button>
            </li>
          )) : null}
        </ul>
        <div className="panel__actions">
          <button
            type="button"
            className="btn"
            disabled={enrolPasskey.isPending}
            onClick={() => setProof({ kind: 'add-passkey' })}
          >
            Add a passkey
          </button>
        </div>
        <p className="field__hint">
          A new credential never authorises its own enrolment, so adding one asks for your password
          first. Enrolling ends every other session this account holds.
        </p>

        <h3>Authenticator app</h3>
        {totpStatus.isPending && otpauth === null ? (
          <p role="status">Checking your authenticator…</p>
        ) : null}
        {totpStatus.isError ? (
          <Alert>Your authenticator state could not be read. Reload to try again.</Alert>
        ) : null}
        {totpEnrolmentInProgress ? (
          <p role="status">
            An enrolment is staged — add it to your authenticator and confirm it with the code below.
          </p>
        ) : totpStatus.isSuccess ? (
          <p role="status">
            {totpStatus.data.confirmed
              ? 'An authenticator is enrolled on this account.'
              : totpStatus.data.pending
                ? 'An enrolment is staged but its one-time seed is no longer shown. Start the enrolment again to get a fresh QR and code.'
                : 'No authenticator is enrolled on this account.'}
          </p>
        ) : null}
        <p>
          A second enrolment is unavailable while an authenticator already stands. Removing one
          asks for your password — never for the code itself, so a stolen phone cannot drop the
          factor it is.
        </p>
        {otpauth !== null && totpEnrolmentInProgress ? (
          <div className="enrolment">
            <QrCode value={otpauth} title="Authenticator setup QR code" />
            <p className="field__hint">
              Scan this with your authenticator, or enter the secret below by hand. Shown exactly
              once: the seed is never retrievable again. Confirming with a code completes the
              enrolment and reissues this session carrying only the password class, so you present
              the new factor separately.
            </p>
            <p className="enrolment__uri mono">{otpauth}</p>
            <div className="field">
              <label htmlFor={codeId}>Code from the authenticator</label>
              <input
                id={codeId}
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(event) => setTotpCode(event.target.value)}
              />
            </div>
            <div className="panel__actions">
              <button
                type="button"
                className="btn btn--primary"
                disabled={totpConfirm.isPending || totpCode.length < 6}
                onClick={() =>
                  totpConfirm.mutate(
                    { code: totpCode },
                    {
                      onSuccess: () => {
                        setOtpauth(null);
                        setTotpCode('');
                        ok('Authenticator enrolled. Present it to step up when you need to.');
                      },
                      onError: report,
                    },
                  )
                }
              >
                Confirm enrolment
              </button>
            </div>
          </div>
        ) : null}
        <div className="panel__actions">
          <button
            type="button"
            className="btn"
            disabled={
              totpStart.isPending || (totpStatus.isSuccess && totpStatus.data.confirmed)
            }
            onClick={() => setProof({ kind: 'totp-start' })}
          >
            Enrol an authenticator
          </button>
          <button
            type="button"
            className="btn"
            disabled={totpRemove.isPending}
            onClick={() => setProof({ kind: 'totp-remove' })}
          >
            Remove the authenticator
          </button>
        </div>
      </Panel>

      <Panel id="account-recovery" title="Recovery">
        <p>
          Recovery codes restore <strong>access</strong> when every factor is gone. They never
          satisfy a disclosure reauthentication, and they never authorise their own regeneration —
          the proof is a code from your authenticator where one stands, otherwise your password.
        </p>
        <div className="panel__actions">
          <button
            type="button"
            className="btn"
            disabled={regenerate.isPending}
            onClick={() => setProof({ kind: 'recovery' })}
          >
            Replace recovery codes
          </button>
        </div>
        <p className="field__hint">
          Replacing them invalidates the previous batch atomically, and the new codes are displayed
          once.
        </p>
      </Panel>

      <Panel id="account-sessions" title="Active sessions">
        <p>
          Every artifact currently holding your account. A <span className="mono">workspace</span>{' '}
          session belongs to another instance&apos;s shell operating this one as you — revoking it
          ends that immediately, mid-flight, because the row is re-resolved on the next request.
        </p>
        {sessions.isError ? (
          <Alert>Your sessions could not be loaded. Reload to try again.</Alert>
        ) : null}
        {sessions.isSuccess && sessions.data.items.length === 0 ? (
          <p role="status">No active sessions.</p>
        ) : null}
        <ul className="sessions">
          {sessions.isSuccess ? sessions.data.items.map((item) => (
            <li key={item.id} className="session">
              <div className="session__head">
                {/* The artifact type is text in a badge, never a colour: it is
                    the single most load-bearing fact in the row. */}
                <span className="badge" data-artifact={item.artifact}>
                  {item.artifact}
                </span>
                <span className="mono session__id">{item.id}</span>
              </div>
              <p className="session__detail">{sessionDetail(item)}</p>
              <button
                className="btn"
                type="button"
                aria-label={`Revoke the ${item.artifact} session ${item.id}`}
                onClick={() =>
                  revokeSession.mutate(item.id, {
                    onSuccess: () => ok(`Revoked the ${item.artifact} session ${item.id}.`),
                    onError: report,
                  })
                }
                disabled={revokeSession.isPending}
              >
                Revoke
              </button>
            </li>
          )) : null}
        </ul>
      </Panel>

      <Panel id="account-identities" title="Linked identities">
        <p>
          An external identity is an explicit binding of (issuer, subject) to this account. An
          unknown identity at sign-in is never a login, and an email address never links anything.
        </p>
        {identities.isError ? <Alert>Your linked identities could not be listed.</Alert> : null}
        {identities.isSuccess && identities.data.identities.length === 0 ? (
          <p role="status">No external identity is linked to this account.</p>
        ) : null}
        <ul className="factors">
          {identities.isSuccess ? identities.data.identities.map((identity) => (
            <li className="factor" key={identity.id}>
              <div>
                <strong className="mono">{identity.issuer}</strong>
                <span className="factor__meta mono">
                  subject {identity.subject} · {identity.kind} · linked{' '}
                  {new Date(identity.created_at).toLocaleDateString()}
                </span>
              </div>
              <button
                type="button"
                className="btn"
                aria-label={`Unlink ${identity.issuer}`}
                onClick={() => setProof({ kind: 'unlink', id: identity.id })}
              >
                Unlink
              </button>
            </li>
          )) : null}
        </ul>
        {methods.isPending ? <p role="status">Loading configured identity providers…</p> : null}
        {methods.isError ? <Alert>Configured identity providers could not be loaded.</Alert> : null}
        {methods.isSuccess && methods.data.providers.length === 0 ? (
          <p role="status">
            Linking starts at a configured identity provider. This instance has none enabled, so
            there is nothing to link to.
          </p>
        ) : null}
        {methods.isSuccess && methods.data.providers.length > 0 ? (
          <>
            <div className="panel__actions">
              {methods.data.providers.map((provider) => (
                <button
                  type="button"
                  className="btn"
                  key={provider.slug}
                  disabled={link.isPending}
                  onClick={() =>
                    setProof({
                      kind: 'link',
                      provider: provider.slug,
                      providerKind: provider.kind,
                    })
                  }
                >
                  Link {provider.display_name}
                </button>
              ))}
            </div>
            <p className="field__hint">
              Linking verifies your existing credential here, then redirects with purpose = link.
              A normal sign-in uses purpose = login and cannot create this binding.
            </p>
          </>
        ) : null}
      </Panel>

      <Panel id="account-preferences" title="Preferences">
        <ThemePreference />
        <p className="field__hint">
          The theme is this browser&apos;s choice and is stored here, not on the account: nothing in
          the contract carries a preference, and a setting that silently failed to follow you would
          be worse than one that never claimed to.
        </p>
      </Panel>

      {proof === null ? null : (
        <ProofDialog
          request={proof}
          onCancel={() => setProof(null)}
          onSubmit={runProof}
        />
      )}

      {codes === null ? null : <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />}
    </div>
  );
}

type ProofRequest =
  | { kind: 'add-passkey' }
  | { kind: 'remove-passkey'; id: string }
  | { kind: 'totp-start' }
  | { kind: 'totp-remove' }
  | { kind: 'recovery' }
  | { kind: 'link'; provider: string; providerKind: 'oidc' | 'saml' }
  | { kind: 'unlink'; id: string };

const PROOF_COPY: Record<ProofRequest['kind'], { title: string; hint: string; label: string }> = {
  'add-passkey': {
    title: 'Confirm it is you',
    hint: 'Enrolling a passkey is an account-security change, so the credential you already have authorises it — the new one never authorises itself.',
    label: 'Password',
  },
  'remove-passkey': {
    title: 'Confirm it is you',
    hint: 'Removing a credential is proved by your password, never by the credential being removed.',
    label: 'Password',
  },
  'totp-start': {
    title: 'Confirm it is you',
    hint: 'Starting an authenticator enrolment stages an inert seed. Nothing changes until you confirm it with a code.',
    label: 'Password',
  },
  'totp-remove': {
    title: 'Confirm it is you',
    hint: 'The factor being removed is excluded from the proof, so a stolen phone alone cannot drop the very factor it is.',
    label: 'Password',
  },
  recovery: {
    title: 'Confirm it is you',
    hint: 'A code from your authenticator where one stands, otherwise your password. Recovery codes never authorise their own regeneration.',
    label: 'Code or password',
  },
  link: {
    title: 'Confirm it is you',
    hint: 'Linking starts from this authenticated account. Your existing password authorises the provider round trip; an ordinary sign-in cannot link identities.',
    label: 'Password',
  },
  unlink: {
    title: 'Confirm it is you',
    hint: 'Unlinking an identity is an account-security change, proved by your password. Removing the last way in is refused.',
    label: 'Password',
  },
};

function ProofDialog({
  request,
  onCancel,
  onSubmit,
}: {
  request: ProofRequest;
  onCancel: () => void;
  onSubmit: (value: string) => void;
}) {
  const dialog = useModalDialog();
  const inputId = useId();
  const [value, setValue] = useState('');
  const copy = PROOF_COPY[request.kind];

  return (
    <dialog
      className="ceremony"
      ref={dialog}
      aria-labelledby="proof-title"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <h2 id="proof-title">{copy.title}</h2>
      <p className="ceremony__lede">{copy.hint}</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit(value);
        }}
      >
        <div className="field">
          <label htmlFor={inputId}>{copy.label}</label>
          <input
            id={inputId}
            type="password"
            autoComplete="current-password"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        </div>
        <div className="ceremony__actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn btn--primary" disabled={value === ''}>
            Confirm
          </button>
        </div>
      </form>
    </dialog>
  );
}

/**
 * RecoveryCodes is the display-once presentation: the codes exist in exactly
 * this response and nowhere else, so the dialog will not close until the human
 * says they have stored them.
 */
function RecoveryCodes({ codes, onClose }: { codes: readonly string[]; onClose: () => void }) {
  const dialog = useModalDialog();
  const ackId = useId();
  const [stored, setStored] = useState(false);
  const [cancelAttempted, setCancelAttempted] = useState(false);

  return (
    <dialog
      className="ceremony"
      ref={dialog}
      aria-labelledby="codes-title"
      onCancel={(event) => {
        event.preventDefault();
        setCancelAttempted(true);
      }}
    >
      <h2 id="codes-title">Your new recovery codes</h2>
      <p className="ceremony__lede">
        Shown once. They are stored as hashes, so nobody — including this instance — can show them
        to you again. The previous batch is already invalid.
      </p>
      <ul className="codes" aria-label="Recovery codes">
        {codes.map((code) => (
          <li className="mono" key={code}>
            {code}
          </li>
        ))}
      </ul>
      {cancelAttempted ? (
        <Alert>
          These codes cannot be dismissed yet. Store them, then acknowledge that below; the
          previous batch is already invalid.
        </Alert>
      ) : null}
      <div className="field chk">
        <input
          id={ackId}
          type="checkbox"
          checked={stored}
          onChange={(event) => setStored(event.target.checked)}
        />
        <label htmlFor={ackId}>I have stored these somewhere safe.</label>
      </div>
      <div className="ceremony__actions">
        <button type="button" className="btn btn--primary" disabled={!stored} onClick={onClose}>
          Done
        </button>
      </div>
    </dialog>
  );
}

/**
 * QrCode renders `value` as a scannable QR built as inline SVG. It is inline
 * and not an `<img src="data:…">` because the CSP's `img-src 'self'` forbids
 * data-URL images. The modules are one `<path>`, painted black on white
 * regardless of theme — a scanner needs the contrast, and `forced-color-adjust`
 * keeps the OS from repainting it into an unscannable pair.
 */
function QrCode({ value, title }: { value: string; title: string }) {
  const { path, count } = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(value);
    qr.make();
    const modules = qr.getModuleCount();
    let d = '';
    for (let row = 0; row < modules; row += 1) {
      for (let col = 0; col < modules; col += 1) {
        if (qr.isDark(row, col)) {
          d += `M${String(col)} ${String(row)}h1v1h-1z`;
        }
      }
    }
    return { path: d, count: modules };
  }, [value]);

  const quiet = 4; // the spec's four-module quiet zone
  const box = count + quiet * 2;
  return (
    <svg
      className="totp-qr"
      viewBox={`0 0 ${String(box)} ${String(box)}`}
      width="176"
      height="176"
      role="img"
      aria-label={title}
      shapeRendering="crispEdges"
    >
      <rect width={box} height={box} fill="#ffffff" />
      <path d={path} transform={`translate(${String(quiet)} ${String(quiet)})`} fill="#000000" />
    </svg>
  );
}

function ThemePreference() {
  const id = useId();
  const [choice, setChoice] = useThemeChoice();

  return (
    <div className="field">
      <label htmlFor={id}>Theme</label>
      <select id={id} value={choice} onChange={(event) => setChoice(themeOf(event.target.value))}>
        <option value="system">{themeLabel('system')}</option>
        <option value="dark">{themeLabel('dark')}</option>
        <option value="light">{themeLabel('light')}</option>
      </select>
    </div>
  );
}

function themeOf(value: string): ThemeChoice {
  if (value === 'dark' || value === 'light' || value === 'system') {
    return value;
  }
  throw new Error(`unknown theme choice ${value}`);
}

/**
 * sessionDetail is the row's sentence. The requesting origin is stated first
 * for a workspace session because it is the thing being judged.
 */
function sessionDetail(session: ActiveSession): string {
  const seen = `last seen ${new Date(session.last_seen_at).toLocaleString()}`;
  if (session.requesting_origin !== undefined) {
    return `Issued to ${session.requesting_origin} — ${seen}.`;
  }
  const where = session.source_ip === undefined ? '' : ` from ${session.source_ip}`;
  return `Signed in with ${session.auth_method}${where} — ${seen}.`;
}
