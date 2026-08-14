import { useEffect, useRef, useState } from 'react';
import { generatePath, Link } from 'react-router';

import type {
  MatrixKeyList,
  MatrixRef,
  MatrixSignalCell,
} from '../api/matrix.ts';
import type { EnvironmentList, ValueCell } from '../api/values.ts';
import { surfaceById } from '../app/navigation.ts';
import { Ceremony } from './Ceremony.tsx';
import { copyRequiresProtectedConfirmation } from './matrix-state.ts';
import {
  useProtectedPublishCeremony,
  type ProtectedPublishTarget,
} from './useProtectedPublishCeremony.ts';

type MatrixKey = MatrixKeyList['items'][number];
type Environment = EnvironmentList['items'][number];

/** Bottom-sheet editor owns one cell's draft, copy selection, and protected copy guard. */
export function MatrixRowEditor({
  refData,
  keyRecord,
  environment,
  environments,
  protectedEnvironmentIds,
  cell,
  signal,
  problems,
  busy,
  onClose,
  onSave,
  onClear,
  onCopy,
}: {
  refData: MatrixRef;
  keyRecord: MatrixKey;
  environment: Environment;
  environments: readonly Environment[];
  protectedEnvironmentIds: readonly string[];
  cell: ValueCell | undefined;
  signal: MatrixSignalCell | undefined;
  problems: readonly { readonly message: string }[];
  busy: boolean;
  onClose: () => void;
  onSave: (value: string) => void;
  onClear: () => void;
  onCopy: (destinations: readonly string[], confirmProtected: boolean) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [draft, setDraft] = useState(
    keyRecord.classification === 'config' && cell?.set === true ? cell.value ?? '' : '',
  );
  const [dirty, setDirty] = useState(false);
  const [copyOpen, setCopyOpen] = useState(false);
  const [destinations, setDestinations] = useState<readonly string[]>([]);
  const [protectedCopyConfirmed, setProtectedCopyConfirmed] = useState(false);
  const protectedGuard = useProtectedPublishCeremony(refData);

  useEffect(() => {
    dialog.current?.showModal();
    return () => dialog.current?.close();
  }, []);

  const valuesPath = generatePath(surfaceById('values').path, {
    org: refData.org,
    project: refData.project,
    environment: environment.id,
  });
  const sourceSet = cell?.set === true;
  const protectedConfirmationRequired = copyRequiresProtectedConfirmation(
    destinations,
    protectedEnvironmentIds,
  );
  const protectedDestinationNames = environments
    .filter(
      (candidate) =>
        destinations.includes(candidate.id) && protectedEnvironmentIds.includes(candidate.id),
    )
    .map((candidate) => candidate.name);

  const protectedTargets = (): readonly ProtectedPublishTarget[] =>
    destinations
      .filter((environmentId) => protectedEnvironmentIds.includes(environmentId))
      .map((environmentId) => {
        const destination = environments.find((candidate) => candidate.id === environmentId);
        if (destination === undefined) {
          throw new Error(`protected copy destination ${environmentId} is not in the matrix`);
        }
        return {
          environmentId,
          environmentName: destination.name,
          keys: [{ id: keyRecord.id, name: keyRecord.name }],
        };
      });

  return (
    <>
      <dialog className="matrix-editor" ref={dialog} onClose={onClose}>
        <form
          method="dialog"
          onSubmit={(event) => {
            event.preventDefault();
            if (dirty) onSave(draft);
          }}
        >
          <div className="matrix-editor__head">
            <div>
              <h2 className="mono">
                {keyRecord.classification === 'secret' ? (
                  <span aria-hidden="true">🔒 </span>
                ) : null}
                {keyRecord.name}
              </h2>
              <p>
                <strong>{environment.name}</strong> · explicit {sourceSet ? 'set' : 'absent'} value
              </p>
            </div>
            <button
              type="button"
              className="btn matrix-editor__close"
              aria-label="Close row editor"
              onClick={onClose}
            >
              ✕
            </button>
          </div>

          {problems.map((problem) => (
            <p className="alert" role="alert" key={problem.message}>
              <span className="alert__glyph" aria-hidden="true">!</span>
              <span>{problem.message}</span>
            </p>
          ))}

          <dl className="matrix-editor__provenance">
            <div><dt>State</dt><dd>{sourceSet ? 'set' : 'absent'}</dd></div>
            <div>
              <dt>Updated</dt>
              <dd>
                {cell?.updated_at === undefined
                  ? 'No published value'
                  : formatTimestamp(cell.updated_at)}
              </dd>
            </div>
            <div><dt>Updated by</dt><dd className="mono">{cell?.updated_by ?? '—'}</dd></div>
            <div>
              <dt>Revision</dt>
              <dd>
                {signal?.changed_in_revision === undefined
                  ? 'No change signal'
                  : `r${String(signal.changed_in_revision)}`}
              </dd>
            </div>
            {signal?.pending_operation === undefined ? null : (
              <div>
                <dt>Draft</dt>
                <dd>{`Δ ${signal.pending_operation === 'unset' ? 'clear' : 'set'} pending`}</dd>
              </div>
            )}
          </dl>

          <div className="field">
            <label htmlFor="matrix-edit-value">New value</label>
            <textarea
              id="matrix-edit-value"
              className="mono matrix-editor__value"
              rows={keyRecord.declaration.rule?.type === 'json' ? 6 : 3}
              autoComplete="off"
              value={draft}
              placeholder={
                keyRecord.classification === 'secret'
                  ? 'Replace without seeing the current secret'
                  : sourceSet
                    ? 'Edit the explicit value'
                    : 'Set an explicit value'
              }
              onChange={(event) => {
                setDraft(event.target.value);
                setDirty(true);
              }}
            />
          </div>
          {keyRecord.classification === 'secret' ? (
            <p className="matrix-editor__hint">
              Current secret stays hidden here. Open Values to reveal it through the disclosure
              ceremony.
            </p>
          ) : null}

          <div className="matrix-editor__actions">
            <button type="submit" className="btn btn--primary" disabled={!dirty || busy}>
              {busy ? 'Saving…' : 'Save draft'}
            </button>
            <button type="button" className="btn" disabled={busy || !sourceSet} onClick={onClear}>
              Clear to absent
            </button>
            <Link className="btn" to={valuesPath}>Open Values</Link>
            {keyRecord.classification === 'config' && sourceSet ? (
              <button
                type="button"
                className="btn"
                aria-expanded={copyOpen}
                onClick={() => setCopyOpen((open) => !open)}
              >
                Copy to…
              </button>
            ) : null}
          </div>

          {copyOpen ? (
            <fieldset className="matrix-editor__copy">
              <legend>Copy independent value to</legend>
              {environments
                .filter((candidate) => candidate.id !== environment.id)
                .map((candidate) => (
                  <label key={candidate.id}>
                    <input
                      type="checkbox"
                      checked={destinations.includes(candidate.id)}
                      onChange={() => {
                        setDestinations((current) =>
                          current.includes(candidate.id)
                            ? current.filter((id) => id !== candidate.id)
                            : [...current, candidate.id],
                        );
                        setProtectedCopyConfirmed(false);
                      }}
                    />
                    <span>
                      {candidate.name}
                      {protectedEnvironmentIds.includes(candidate.id) ? ' · protected' : ''}
                    </span>
                  </label>
                ))}
              {protectedConfirmationRequired ? (
                <label className="matrix-editor__protected-confirmation">
                  <input
                    type="checkbox"
                    checked={protectedCopyConfirmed}
                    onChange={(event) => setProtectedCopyConfirmed(event.target.checked)}
                  />
                  <span>
                    I confirm copying into protected {protectedDestinationNames.join(', ')}.
                  </span>
                </label>
              ) : null}
              {protectedGuard.error === null ? null : (
                <p className="alert" role="alert">
                  <span className="alert__glyph" aria-hidden="true">!</span>
                  <span>{protectedGuard.error}</span>
                </p>
              )}
              <p>Each copied value is independent; later source edits do not propagate.</p>
              <button
                type="button"
                className="btn"
                disabled={
                  destinations.length === 0 ||
                  busy ||
                  (protectedConfirmationRequired && !protectedCopyConfirmed)
                }
                onClick={() => {
                  void protectedGuard.run(
                    protectedTargets(),
                    () => onCopy(destinations, protectedConfirmationRequired),
                    'The protected destination guard could not be read, so nothing was copied',
                  );
                }}
              >
                {`Copy to ${String(destinations.length)} environment${destinations.length === 1 ? '' : 's'}`}
              </button>
            </fieldset>
          ) : null}
        </form>
      </dialog>
      {protectedGuard.request === null ? null : (
        <Ceremony
          request={protectedGuard.request}
          onAuthorised={protectedGuard.onAuthorised}
          onCancel={protectedGuard.onCancel}
        />
      )}
    </>
  );
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(value),
  );
}
