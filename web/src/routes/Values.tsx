import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router';

import {
  disclosureRefusalText,
  fetchRevealWindow,
  useCopyValues,
  useEnvironments,
  useRevealAll,
  useRevealOne,
  useRevealWindow,
  useSetValue,
  useValues,
  type EnvRef,
  type RevealWindow,
  type ValueCell,
} from '../api/values.ts';
import { useTransport } from '../api/transport.tsx';
import { Ceremony, type CeremonyPurpose, type CeremonyRequest } from './Ceremony.tsx';

/**
 * The reveal / copy / write-only-edit surface (#58, locked prototype #21).
 *
 * The rules this surface exists to make real, each one from the permission
 * model or the frozen prototype:
 *
 *  - **The window gates the prompt, never the check.** Before a disclosure the
 *    surface asks the server whether a window is live. If one is, it discloses
 *    without a modal; if not, it runs the ceremony first. A refusal from the
 *    disclosure route itself is NOT a cue to prompt again — it remasks and
 *    says so, because the usual cause is a grant that went away underneath an
 *    open window.
 *  - **Auto-remask with a visible countdown.** A revealed value re-masks after
 *    a short interval, counted down on the cell, so nothing is left on a
 *    screen someone walked away from.
 *  - **Clipboard is an audited disclosure**, including copy-without-display
 *    from the masked state. Non-secret copy is free. The clipboard is cleared
 *    best-effort afterwards, with microcopy that does not overclaim.
 *  - **Write-only editing is a first-class path.** A key you may `edit` but
 *    not `reveal` gets a replacement field and a placeholder that says what it
 *    is, never a disabled input.
 *  - **Copy into a protected environment runs the same enumerated-key
 *    ceremony** as a reveal. There is no `confirm()` anywhere on this surface.
 */

/** REMASK_MS is the 10s-class default the prototype fixed; the exact value becomes a project setting. */
const REMASK_MS = 10_000;
/** CLIPBOARD_CLEAR_MS is the best-effort clipboard clear the prototype fixed at 45s. */
const CLIPBOARD_CLEAR_MS = 45_000;

const MASK = '••••••••';

/**
 * AUDIT_LINES is how many disclosure records the surface keeps on screen.
 *
 * It bounds the panel, never the trail: every disclosure is a durable audit
 * row on the server whatever this says, and one line per key is the property
 * that matters — this is only how far back the human can scroll without
 * leaving the page.
 */
const AUDIT_LINES = 12;

type Disclosed = { value: string; until: number };

/**
 * cellKey identifies a disclosed cell by ENVIRONMENT and key id.
 *
 * Key names repeat across environments — that is the point of the model — so a
 * map keyed by name alone would let development's `DB_PASSWORD` render in
 * production's row. The environment is in the key as well as being cleared on
 * navigation, because the two failures are different: one is a stale map, the
 * other is a map that was never wrong but is being read against the wrong
 * environment.
 */
function cellKey(environment: string, keyID: string): string {
  return `${environment}/${keyID}`;
}

export function Values() {
  const params = useParams();
  const env: EnvRef = {
    org: params['org'] ?? '',
    project: params['project'] ?? '',
    environment: params['environment'] ?? '',
  };

  const transport = useTransport();
  const values = useValues(env);
  const environmentsQuery = useEnvironments(env);
  const revealGuard = useRevealWindow(env);
  const revealOne = useRevealOne(env);
  const revealAll = useRevealAll(env);
  const setValue = useSetValue(env);
  const copy = useCopyValues(env);

  const [disclosed, setDisclosed] = useState<Record<string, Disclosed>>({});
  const [now, setNow] = useState(() => Date.now());
  const [refusal, setRefusal] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [audit, setAudit] = useState<string[]>([]);
  const [pending, setPending] = useState<CeremonyRequest | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [destination, setDestination] = useState('');
  const resume = useRef<(() => void) | null>(null);

  // NAVIGATION RE-MASKS. React Router reuses this component when only the
  // route parameters change, so without this a value disclosed in development
  // would still be in state — and on screen — a moment after the human moved
  // to production. Everything transient goes: the plaintext, a ceremony
  // waiting to be answered, the act it was staged for, an open editor and the
  // clipboard notice, none of which mean anything in a different environment.
  useEffect(() => {
    setDisclosed({});
    setPending(null);
    setEditing(null);
    setRefusal(null);
    setNotice(null);
    setAudit([]);
    resume.current = null;
  }, [env.org, env.project, env.environment]);

  // One ticker drives every countdown on the surface: the remask timers and
  // the window chip are the same question asked of different deadlines, and a
  // timer per cell is a timer per cell to leak.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);

  // Remasking is DERIVED from the deadline rather than scheduled: a tab that
  // was backgrounded past the deadline comes back masked, which a
  // setTimeout-per-cell does not guarantee.
  useEffect(() => {
    setDisclosed((current) => {
      const live = Object.entries(current).filter(([, d]) => d.until > Date.now());
      return live.length === Object.keys(current).length ? current : Object.fromEntries(live);
    });
  }, [now]);

  const cells: ValueCell[] = useMemo(() => values.data?.items ?? [], [values.data]);
  // The modal title is purpose-bound — `reveal · production` — so it needs the
  // environment's NAME. Until the list resolves the id is the honest stand-in:
  // showing nothing would make the ceremony's headline blank, which is worse
  // than showing an identifier.
  const environments = useMemo(() => environmentsQuery.data?.items ?? [], [environmentsQuery.data]);
  const nameOf = useCallback(
    (id: string) => environments.find((candidate) => candidate.id === id)?.name ?? id,
    [environments],
  );
  const environmentName = nameOf(env.environment);
  const destinationName = nameOf(destination);
  const guard: RevealWindow | undefined = revealGuard.data;

  const secretsSet = useMemo(
    () => cells.filter((c) => c.classification === 'secret' && c.set),
    [cells],
  );

  /**
   * withCeremony is the one place the "prompt or not" decision is made.
   *
   * `targets` is every environment the act needs authority over, in the order
   * the server will judge them: a reveal names one, a publish names two — the
   * SOURCE it discloses from and the DESTINATION it delivers into, each with
   * its own window and its own protected flag. A live window on one is not
   * authority over the other, which is exactly what a protected environment's
   * cap exists to say, so each target that is not already covered gets its own
   * decision and the act runs only once every one of them is.
   *
   * The guard's state is fetched, never remembered: an environment marked
   * protected while the tab was open caps its window at 0, and a client
   * extrapolating from its own last ceremony would skip a prompt the server is
   * about to demand.
   */
  const withCeremony = useCallback(
    async (
      keys: ReadonlyArray<{ id: string; name: string }>,
      act: () => Promise<void>,
      targets: ReadonlyArray<{ id: string; name: string; purpose: CeremonyPurpose }>,
    ) => {
      setRefusal(null);
      for (let i = 0; i < targets.length; i++) {
        const target = targets[i];
        if (target === undefined) {
          continue;
        }
        let state: RevealWindow;
        try {
          state = await fetchRevealWindow({ ...env, environment: target.id }, transport.client);
        } catch {
          setRefusal('The reveal window could not be read, so nothing was disclosed.');
          return;
        }
        if (state.live && !state.single_decision) {
          continue;
        }
        // This target needs a decision. Stage it, and resume with the targets
        // this loop has not reached yet — so a two-ceremony act asks twice and
        // never runs on one answer.
        const remaining = targets.slice(i + 1);
        resume.current = () => {
          void withCeremony(keys, act, remaining);
        };
        setPending({
          purpose: target.purpose,
          environmentId: target.id,
          environmentName: target.name,
          keys,
          window: state,
        });
        return;
      }
      await act();
    },
    [env, transport.client],
  );

  const noteDisclosure = useCallback((names: string[]) => {
    // One line per key. "Revealed 40 secrets" as a single line is the audit
    // shape the ADR forbids, and a UI that summarises trains people to expect
    // a trail that summarises.
    setAudit((prev) => [...names.map((n) => `Disclosure recorded · ${n}`), ...prev].slice(0, AUDIT_LINES));
  }, []);

  const show = useCallback(
    (entries: Array<{ id: string; name: string; value: string }>) => {
      const until = Date.now() + REMASK_MS;
      setDisclosed((current) => {
        const next = { ...current };
        for (const entry of entries) {
          next[cellKey(env.environment, entry.id)] = { value: entry.value, until };
        }
        return next;
      });
      noteDisclosure(entries.map((e) => e.name));
    },
    [env.environment, noteDisclosure],
  );

  const doRevealOne = (cell: ValueCell) =>
    void withCeremony(
      [{ id: cell.key_id, name: cell.name }],
      async () => {
        try {
          const fresh = await revealOne.mutateAsync(cell.name);
          if (fresh.value === undefined) {
            setRefusal('The server disclosed no value for that key.');
            return;
          }
          show([{ id: fresh.key_id, name: fresh.name, value: fresh.value }]);
        } catch (err) {
          setDisclosed({});
          setRefusal(disclosureRefusalText(err));
        }
      },
      [{ id: env.environment, name: environmentName, purpose: 'reveal' }],
    );

  const doRevealAll = () =>
    void withCeremony(
      secretsSet.map((c) => ({ id: c.key_id, name: c.name })),
      async () => {
        try {
          const fresh = await revealAll.mutateAsync();
          show(
            fresh.items
              .filter((c) => c.classification === 'secret' && c.value !== undefined)
              .map((c) => ({ id: c.key_id, name: c.name, value: c.value ?? '' })),
          );
        } catch (err) {
          setDisclosed({});
          setRefusal(disclosureRefusalText(err));
        }
      },
      [{ id: env.environment, name: environmentName, purpose: 'reveal' }],
    );

  /**
   * doCopy is clipboard-as-disclosure, and it works from the MASKED state.
   *
   * A `config` value is already on screen under plain `read`, so copying it is
   * free and takes no ceremony. A `secret` runs the full gate whether or not
   * the human ever saw it: copy-without-display puts the plaintext somewhere
   * the actor controls, which is a disclosure by the ADR's own definition.
   */
  const doCopy = (cell: ValueCell) => {
    if (cell.classification !== 'secret') {
      void writeClipboard(cell.value ?? '', setNotice, false);
      return;
    }
    void withCeremony(
      [{ id: cell.key_id, name: cell.name }],
      async () => {
        try {
          const fresh = await revealOne.mutateAsync(cell.name);
          if (fresh.value === undefined) {
            setRefusal('The server disclosed no value for that key.');
            return;
          }
          noteDisclosure([fresh.name]);
          await writeClipboard(fresh.value, setNotice, true);
        } catch (err) {
          setRefusal(disclosureRefusalText(err));
        }
      },
      [{ id: env.environment, name: environmentName, purpose: 'clipboard' }],
    );
  };

  const doPublishInto = () => {
    if (secretsSet.length === 0 || destination === '') {
      return;
    }
    void withCeremony(
      secretsSet.map((c) => ({ id: c.key_id, name: c.name })),
      async () => {
        try {
          await copy.mutateAsync({
            keys: secretsSet.map((c) => c.name),
            destinations: [destination],
          });
          setAudit((prev) =>
            [...secretsSet.map((c) => `Copied into ${destination} · ${c.name}`), ...prev].slice(
              0,
              12,
            ),
          );
        } catch (err) {
          setRefusal(disclosureRefusalText(err));
        }
      },
      // TWO decisions, in the order the server judges them: the material leaves
      // this environment (a disclosure) and lands in that one (which, when it
      // is protected, is the publish-into-protected ceremony).
      [
        { id: env.environment, name: environmentName, purpose: 'copy' },
        { id: destination, name: destinationName, purpose: 'publish' },
      ],
    );
  };

  const chip = guard === undefined ? null : windowChip(guard, now);

  return (
    <section className="card values" aria-labelledby="well-title">
      <header className="values__head">
        <h1 id="well-title">Values</h1>
        {chip}
      </header>

      {values.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>The values could not be loaded. Reload to try again.</span>
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

      {notice !== null ? (
        <p className="notice" role="status">
          <span className="alert__glyph" aria-hidden="true">
            ⧉
          </span>
          <span>{notice}</span>
        </p>
      ) : null}

      <div className="values__bar">
        <button
          className="btn"
          type="button"
          onClick={doRevealAll}
          disabled={secretsSet.length === 0 || guard?.can_reveal === false}
        >
          Reveal every secret
        </button>
        <div className="field field--inline">
          <label htmlFor="publish-destination">Publish into</label>
          <select
            id="publish-destination"
            value={destination}
            onChange={(event) => setDestination(event.target.value)}
          >
            <option value="">Choose an environment…</option>
            {environments
              .filter((candidate) => candidate.id !== env.environment)
              .map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.name}
                </option>
              ))}
          </select>
        </div>
        <button
          className="btn"
          type="button"
          onClick={doPublishInto}
          disabled={secretsSet.length === 0 || destination === ''}
        >
          Publish into environment
        </button>
      </div>

      <table className="values__table">
        <caption className="visually-hidden">
          Values in this environment. Secret values are masked until disclosed.
        </caption>
        <thead>
          <tr>
            <th scope="col">Key</th>
            <th scope="col">Value</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {cells.map((cell) => {
            const live = disclosed[cellKey(env.environment, cell.key_id)];
            const remaining =
              live === undefined ? 0 : Math.max(0, Math.ceil((live.until - now) / 1000));
            const secret = cell.classification === 'secret';
            // WRITE-ONLY IS A CAPABILITY, not a display state. `edit` without
            // `reveal` is a supported grant shape the permission model refuses
            // to reject, and the guard reports whether this principal holds
            // `reveal` here — so the editor says "replace without seeing" to
            // someone who genuinely cannot read the value, and keeps saying it
            // while they are looking at nothing. Deriving it from whether the
            // cell happens to be revealed on screen would make the microcopy a
            // function of what the human last clicked.
            const writeOnly = secret && guard !== undefined && !guard.can_reveal;
            return (
              <tr key={cell.key_id}>
                <th scope="row">
                  <button
                    className="values__keyname mono"
                    type="button"
                    onClick={() => setEditing(editing === cell.name ? null : cell.name)}
                    aria-expanded={editing === cell.name}
                  >
                    {cell.name}
                  </button>
                </th>
                <td>
                  {!cell.set ? (
                    <span className="values__absent">absent</span>
                  ) : live !== undefined ? (
                    <span className="mono values__plain">
                      {live.value}
                      <span className="values__countdown" role="status">
                        {`re-masks in ${remaining}s`}
                      </span>
                    </span>
                  ) : secret ? (
                    <span className="mono values__masked" aria-label={`${cell.name} is masked`}>
                      {MASK}
                    </span>
                  ) : (
                    <span className="mono values__plain">{cell.value ?? ''}</span>
                  )}
                </td>
                <td className="values__actions">
                  {secret && cell.set && !writeOnly ? (
                    <button
                      className="btn"
                      type="button"
                      onClick={() => doRevealOne(cell)}
                      aria-label={`Reveal ${cell.name}`}
                    >
                      Reveal
                    </button>
                  ) : null}
                  {cell.set ? (
                    <button
                      className="btn"
                      type="button"
                      onClick={() => doCopy(cell)}
                      aria-label={`Copy ${cell.name}`}
                    >
                      Copy
                    </button>
                  ) : null}
                </td>
                {editing === cell.name ? (
                  <td className="values__editor">
                    <RowEditor
                      cell={cell}
                      writeOnly={writeOnly}
                      onSave={(value) => {
                        setEditing(null);
                        // Empty means UNCHANGED. There is no per-row clear:
                        // clearing a value stays a per-cell action, as the
                        // prototype's resolution fixed.
                        if (value !== '') {
                          setValue.mutate({ key: cell.name, value });
                        }
                      }}
                    />
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>

      <section className="values__audit" aria-label="Disclosure records">
        <h2>Recorded this session</h2>
        {audit.length === 0 ? (
          <p role="status">No disclosures yet.</p>
        ) : (
          // The live region is the LIST, not each item. An explicit role on an
          // `li` replaces its implicit `listitem` role, which would leave the
          // list with no items as far as assistive technology — and the flow
          // registry's own assertions — are concerned.
          <ul aria-live="polite">
            {audit.map((line, i) => (
              <li key={`${line}-${String(i)}`}>{line}</li>
            ))}
          </ul>
        )}
      </section>

      {pending !== null ? (
        <Ceremony
          request={pending}
          onAuthorised={() => {
            setPending(null);
            const run = resume.current;
            resume.current = null;
            run?.();
          }}
          onCancel={() => {
            setPending(null);
            resume.current = null;
          }}
        />
      ) : null}
    </section>
  );
}

/**
 * windowChip is the countdown the ADR asks the surface to show.
 *
 * A single-decision window gets no countdown, and that is the honest
 * rendering: it is not a period during which disclosures are unlocked, it is
 * one authorisation waiting to be spent, and a ticking number would say
 * otherwise.
 */
function windowChip(state: RevealWindow, now: number) {
  if (!state.live) {
    return (
      <span className="chip" role="status">
        {state.totp_offered
          ? 'Locked · each disclosure asks first'
          : state.protected
            ? 'Protected · a passkey per disclosure'
            : 'Locked · a passkey per disclosure'}
      </span>
    );
  }
  if (state.single_decision) {
    return (
      <span className="chip chip--armed" role="status">
        Authorised for one disclosure
      </span>
    );
  }
  const seconds =
    state.expires_at === undefined
      ? 0
      : Math.max(0, Math.ceil((new Date(state.expires_at).getTime() - now) / 1000));
  return (
    <span className="chip chip--armed" role="status">
      {`Reveal window · ${String(seconds)}s`}
    </span>
  );
}

/**
 * RowEditor is the write path, and it is the same field whether or not the
 * human can read what is there.
 *
 * `writeOnly` changes the PLACEHOLDER, not the capability: a blind rotation is
 * a supported, first-class act, and disabling the field for someone who holds
 * `edit` would invent a prerequisite the permission model explicitly refuses
 * to have.
 */
function RowEditor({
  cell,
  writeOnly,
  onSave,
}: {
  cell: ValueCell;
  writeOnly: boolean;
  onSave: (value: string) => void;
}) {
  const [draft, setDraft] = useState('');
  const id = `edit-${cell.key_id}`;
  return (
    <form
      className="row-editor"
      onSubmit={(event) => {
        event.preventDefault();
        onSave(draft);
      }}
    >
      <div className="field">
        <label htmlFor={id}>{`New value for ${cell.name}`}</label>
        <input
          id={id}
          name="value"
          className="mono"
          autoComplete="off"
          placeholder={
            writeOnly ? 'Replace without seeing the current value' : 'Leave empty to keep unchanged'
          }
          data-write-only={writeOnly}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
      </div>
      {writeOnly ? (
        <p className="row-editor__hint" role="status">
          You may replace this value but not read it. Saving sets a new one; leaving the field empty
          changes nothing.
        </p>
      ) : null}
      <button className="btn btn--primary" type="submit">
        Save draft
      </button>
    </form>
  );
}

/**
 * writeClipboard copies and then clears, best effort, with microcopy that does
 * not overclaim.
 *
 * The caveat is the point: the clear only runs while this tab is focused and
 * the operating system may keep its own clipboard history. Promising "cleared
 * in 45 seconds" full stop would be a promise the browser cannot keep.
 */
async function writeClipboard(
  value: string,
  setNotice: (text: string | null) => void,
  audited: boolean,
): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    setNotice('This browser refused clipboard access, so nothing was copied.');
    return;
  }
  setNotice(
    audited
      ? 'Copied, and recorded as a disclosure. Cleared in 45s if this tab stays focused — the OS may keep clipboard history.'
      : 'Copied. This value is not a secret, so no disclosure was recorded.',
  );
  globalThis.setTimeout(() => {
    if (document.hasFocus()) {
      void navigator.clipboard.writeText('').catch(() => undefined);
    }
  }, CLIPBOARD_CLEAR_MS);
}
