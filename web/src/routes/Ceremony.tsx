import { useRef, useState, type FormEvent } from 'react';

import {
  ceremonyRefusalText,
  runPasskeyCeremony,
  runTOTPCeremony,
  type RevealWindow,
} from '../api/values.ts';
import { useModalDialog } from './useModalDialog.ts';

/**
 * The purpose-bound ceremony modal (#58, locked prototype #21 iteration 6,
 * approach **a** — the centred ceremony modal; the inline popover, the
 * hold-to-reveal cell and the session drawer were all rejected).
 *
 * Four properties are load-bearing and none of them is decoration:
 *
 *  1. **Purpose-bound.** The title names the ACT and the environment
 *     (`reveal · production`), so the human is not agreeing to "authenticate"
 *     in the abstract.
 *  2. **Enumerated key set.** The modal lists exactly the keys the decision
 *     carries, under the sentence that says so, and the same list is what the
 *     challenge is bound to. What is signed and what is shown are one list.
 *  3. **Disclosure reauth is not account step-up.** Said in the modal, because
 *     the two look identical to a human and only one of them ends with a
 *     secret on screen.
 *  4. **A protected environment offers no TOTP option at all.** Not disabled —
 *     absent, with the reason stated. A greyed-out control invites a support
 *     ticket; a sentence explaining that this environment takes a passkey
 *     every time is the answer to the question that ticket would ask.
 *
 * It is a NATIVE `<dialog>` opened with `showModal()`. That is the whole
 * accessibility story rather than a starting point for one: the platform gives
 * a real focus trap (Tab cannot leave), inert content behind it, Escape, and
 * the top layer — every part of which a hand-rolled `role="dialog"` has to
 * reimplement, and the focus trap is the part everyone gets wrong. A ceremony
 * a keyboard user can Tab out of while it is "modal" is a ceremony they can
 * answer without seeing what they are answering about.
 *
 * `<dialog>` already exposes `role="dialog"` and `aria-modal="true"`; both are
 * left implicit rather than restated, because a redundant explicit role is one
 * more thing that can drift from what the element actually is.
 */

/**
 * CeremonyPurpose is what the human is TOLD they are authorising.
 *
 * It is deliberately finer than the operation the assertion signs: taking a
 * secret to the clipboard and putting it on screen are the same disclosure to
 * the server — the same route, the same audit surface — but they are not the
 * same sentence to a person, and the modal owes them the true one.
 */
export type CeremonyPurpose = 'reveal' | 'clipboard' | 'copy' | 'publish' | 'restore' | 'pin';

const PURPOSE_VERB: Record<CeremonyPurpose, string> = {
  reveal: 'reveal',
  clipboard: 'copy to clipboard',
  copy: 'copy',
  publish: 'publish into',
  restore: 'restore an earlier revision of',
  pin: 'pin a historical revision of',
};

/**
 * SIGNED_OPERATION maps what the human is told to what the assertion COMMITS
 * TO, which must be the operation the server will consume — otherwise the
 * ceremony is spent against a binding that does not match and the disclosure
 * is refused for a reason nobody can act on.
 *
 * Clipboard copy signs `reveal` because that is the route it takes: the ADR
 * gates and audits it exactly like a reveal ("clipboard copy is gated and
 * audited exactly like reveal — including copy without display"), and the
 * server cannot tell the two apart because there is nothing to tell apart.
 * `copy` is the source leg of moving material INTO another environment, which
 * is a different route and a different decision.
 */
const SIGNED_OPERATION: Record<CeremonyPurpose, 'reveal' | 'copy' | 'publish'> = {
  reveal: 'reveal',
  clipboard: 'reveal',
  copy: 'copy',
  publish: 'publish',
  // Restore and pin both READ historical secret material: staging an earlier
  // value decrypts it, and pinning a non-current revision routes it to a
  // workload. The service gates both with `PurposeReveal` over the enumerated
  // secret-key unit (`internal/service/{rollback,pins}.go`), so that is what the
  // assertion has to commit to — while the modal still tells the human which of
  // the two decisions they are actually taking.
  restore: 'reveal',
  pin: 'reveal',
};

export type CeremonyRequest = {
  purpose: CeremonyPurpose;
  /** The environment the decision authorises, by id. */
  environmentId: string;
  /** The environment's human name, for the title. */
  environmentName: string;
  /** The enumerated unit: what the modal lists and what the challenge binds. */
  keys: ReadonlyArray<{ id: string; name: string }>;
  /** The guard's state, which decides whether TOTP is on the table. */
  window: RevealWindow;
};

export function Ceremony({
  request,
  onAuthorised,
  onCancel,
}: {
  request: CeremonyRequest;
  onAuthorised: () => void;
  onCancel: () => void;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const first = useRef<HTMLButtonElement>(null);
  const dialog = useModalDialog(first);

  const attempt = async (run: () => Promise<void>) => {
    setBusy(true);
    setFailure(null);
    try {
      await run();
      onAuthorised();
    } catch (err) {
      setFailure(ceremonyRefusalText(err));
    } finally {
      setBusy(false);
    }
  };

  const onPasskey = () =>
    void attempt(() =>
      runPasskeyCeremony({
        operation: SIGNED_OPERATION[request.purpose],
        environmentId: request.environmentId,
        keyIds: request.keys.map((k) => k.id),
      }),
    );

  const onCode = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void attempt(() => runTOTPCeremony(request.environmentId, code));
  };

  const title = `${PURPOSE_VERB[request.purpose]} · ${request.environmentName}`;

  return (
    <dialog
      className="ceremony"
      aria-labelledby="ceremony-title"
      aria-describedby="ceremony-scope"
      ref={dialog}
      // Escape is the platform's, not ours — but the close it fires has to
      // reach the caller, or the modal disappears while the act stays staged.
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <h2 className="ceremony__title" id="ceremony-title">
        {title}
      </h2>
      <p className="ceremony__lede">
        This confirms a <strong>disclosure</strong>, not your account security. It is separate from
        signing in and from any step-up you have already done.
      </p>

      <p className="ceremony__scope" id="ceremony-scope">
        One decision over exactly the {request.keys.length}{' '}
        {request.keys.length === 1 ? 'key' : 'keys'} below.
      </p>
      <ul className="ceremony__keys" aria-label="Keys this decision covers">
        {request.keys.map((key) => (
          <li className="mono" key={key.id}>
            {key.name}
          </li>
        ))}
      </ul>

      {failure !== null ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      ) : null}

      {request.window.totp_offered ? null : (
        // Stated, never a disabled control. "Protected" and "the window is
        // set to 0" are different sentences and the human is owed whichever
        // one is true.
        <p className="ceremony__cap" role="status">
          <span className="alert__glyph" aria-hidden="true">
            ⚿
          </span>
          <span>
            {request.window.protected
              ? 'This environment is protected, so every disclosure takes its own passkey ceremony. A code cannot authorise it.'
              : 'This environment allows no reauthentication window, so every disclosure takes its own passkey ceremony. A code cannot authorise it.'}
          </span>
        </p>
      )}

      <div className="ceremony__actions">
        <button
          className="btn btn--primary"
          type="button"
          ref={first}
          onClick={onPasskey}
          disabled={busy}
        >
          {busy ? 'Waiting for your passkey…' : 'Use a passkey'}
        </button>
        <button className="btn" type="button" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>

      {request.window.totp_offered ? (
        <form className="ceremony__totp" onSubmit={onCode}>
          <div className="field">
            <label htmlFor="ceremony-code">Or a code from your authenticator</label>
            <input
              id="ceremony-code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </div>
          <button className="btn" type="submit" disabled={busy || code.length < 6}>
            Authorise with a code
          </button>
        </form>
      ) : null}
    </dialog>
  );
}
