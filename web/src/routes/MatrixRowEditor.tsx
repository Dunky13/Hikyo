import { useEffect, useMemo, useRef, useState } from 'react';
import { generatePath, Link } from 'react-router';

import type {
  MatrixKeyList,
  MatrixRef,
  MatrixSignalCell,
} from '../api/matrix.ts';
import type { EnvironmentList, ValueCell } from '../api/values.ts';
import { surfaceById } from '../app/navigation.ts';
import { Ceremony } from './Ceremony.tsx';
import {
  canClearMatrixCell,
  copyRequiresProtectedConfirmation,
  draftValueForMatrixCell,
  validateMatrixDraft,
} from './matrix-state.ts';
import {
  useProtectedPublishCeremony,
  type ProtectedPublishTarget,
} from './useProtectedPublishCeremony.ts';

type MatrixKey = MatrixKeyList['items'][number];
type Environment = EnvironmentList['items'][number];

type EditorRow = {
  readonly environment: Environment;
  readonly protected: boolean;
  readonly cell: ValueCell | undefined;
  readonly signal: MatrixSignalCell | undefined;
  readonly draftPreview: string | undefined;
  readonly problems: readonly { readonly message: string }[];
};

export type MatrixEditorChange =
  | { readonly environmentId: string; readonly operation: 'set'; readonly value: string }
  | { readonly environmentId: string; readonly operation: 'unset' };

/** Locked row editor: one independently staged field per readable environment. */
export function MatrixRowEditor({
  refData,
  keyRecord,
  environment,
  environments,
  protectedEnvironmentIds,
  rows,
  busy,
  onClose,
  onApply,
  onCopy,
}: {
  refData: MatrixRef;
  keyRecord: MatrixKey;
  environment: Environment;
  environments: readonly Environment[];
  protectedEnvironmentIds: readonly string[];
  rows: readonly EditorRow[];
  busy: boolean;
  onClose: () => void;
  onApply: (changes: readonly MatrixEditorChange[]) => Promise<void>;
  onCopy: (destinations: readonly string[], confirmProtected: boolean) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const initialDrafts = useMemo(
    () =>
      new Map(
        rows.map((row) => [
          row.environment.id,
          draftValueForMatrixCell(
            keyRecord.classification,
            row.cell?.set === true ? row.cell.value : undefined,
            row.signal?.pending_operation,
            row.draftPreview,
          ),
        ]),
      ),
    [keyRecord.classification, rows],
  );
  const [drafts, setDrafts] = useState<ReadonlyMap<string, string>>(initialDrafts);
  const [dirty, setDirty] = useState<ReadonlySet<string>>(() => new Set());
  const [clears, setClears] = useState<ReadonlySet<string>>(() => new Set());
  const [fillAll, setFillAll] = useState('');
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
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
  const sourceRow = rows.find((row) => row.environment.id === environment.id);
  const sourceSet = sourceRow?.cell?.set === true;
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

  const validationByEnvironment = new Map<string, string>();
  for (const row of rows) {
    if (!dirty.has(row.environment.id) || clears.has(row.environment.id)) {
      continue;
    }
    const value = drafts.get(row.environment.id) ?? '';
    const error = validateDeclaration(keyRecord, value);
    if (error !== null) {
      validationByEnvironment.set(row.environment.id, error);
    }
  }

  const changes = rows.flatMap<MatrixEditorChange>((row) => {
    if (clears.has(row.environment.id)) {
      return [{ environmentId: row.environment.id, operation: 'unset' }];
    }
    const value = drafts.get(row.environment.id) ?? '';
    if (dirty.has(row.environment.id) && value !== '') {
      return [{ environmentId: row.environment.id, operation: 'set', value }];
    }
    return [];
  });

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
      <dialog className="matrix-editor matrix-row-editor" ref={dialog} onClose={onClose}>
        <form
          method="dialog"
          onSubmit={(event) => {
            event.preventDefault();
            if (changes.length === 0 || validationByEnvironment.size > 0) return;
            setApplying(true);
            setApplyError(null);
            void onApply(changes)
              .catch(() => setApplyError('The draft update failed. Fix the named row and retry.'))
              .finally(() => setApplying(false));
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
              <p>One independent draft per readable environment. Empty fields stay unchanged.</p>
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

          <div className="matrix-row-editor__fill">
            <label htmlFor="matrix-fill-all">Fill all environments</label>
            <div>
              <input
                id="matrix-fill-all"
                className="mono"
                type={keyRecord.classification === 'secret' ? 'password' : 'text'}
                autoComplete="off"
                value={fillAll}
                placeholder={keyRecord.classification === 'secret' ? 'Write-only replacement' : 'Shared draft value'}
                onChange={(event) => setFillAll(event.target.value)}
              />
              <button
                type="button"
                className="btn"
                disabled={fillAll === '' || busy || applying}
                onClick={() => {
                  setDrafts(new Map(rows.map((row) => [row.environment.id, fillAll])));
                  setDirty(new Set(rows.map((row) => row.environment.id)));
                  setClears(new Set());
                }}
              >
                Fill all
              </button>
            </div>
          </div>

          <div className="matrix-row-editor__rows">
            {rows.map((row) => {
              const environmentId = row.environment.id;
              const publishedSet = row.cell?.set === true;
              const clearing = clears.has(environmentId);
              const liveError = validationByEnvironment.get(environmentId);
              return (
                <section
                  className={`matrix-row-editor__row${row.protected ? ' matrix-row-editor__row--protected' : ''}`}
                  key={environmentId}
                  aria-labelledby={`matrix-row-${environmentId}`}
                >
                  <div className="matrix-row-editor__row-head">
                    <h3 id={`matrix-row-${environmentId}`}>{row.environment.name}</h3>
                    {row.protected ? <span>PROTECTED</span> : null}
                    <span>{publishedSet ? 'explicit set' : 'explicit absent'}</span>
                    {row.signal?.pending_operation === undefined ? null : (
                      <span>{`Δ ${row.signal.pending_operation} pending`}</span>
                    )}
                  </div>
                  {row.problems.map((problem) => (
                    <p className="alert" role="alert" key={problem.message}>
                      <span className="alert__glyph" aria-hidden="true">!</span>
                      <span>{problem.message}</span>
                    </p>
                  ))}
                  <label htmlFor={`matrix-edit-${environmentId}`}>
                    {`${row.environment.name} value`}
                  </label>
                  <textarea
                    id={`matrix-edit-${environmentId}`}
                    className="mono matrix-editor__value"
                    rows={keyRecord.declaration.rule?.type === 'json' ? 6 : 2}
                    autoComplete="off"
                    value={clearing ? '' : drafts.get(environmentId) ?? ''}
                    placeholder={
                      keyRecord.classification === 'secret'
                        ? publishedSet
                          ? 'Write-only · replace current secret'
                          : 'Write-only · set a new secret'
                        : publishedSet
                          ? 'Edit the explicit value'
                          : 'Empty = unchanged'
                    }
                    aria-invalid={liveError === undefined ? undefined : true}
                    aria-describedby={liveError === undefined ? undefined : `matrix-error-${environmentId}`}
                    onChange={(event) => {
                      const next = new Map(drafts);
                      next.set(environmentId, event.target.value);
                      setDrafts(next);
                      setDirty((current) => new Set(current).add(environmentId));
                      setClears((current) => {
                        const nextClears = new Set(current);
                        nextClears.delete(environmentId);
                        return nextClears;
                      });
                    }}
                  />
                  {liveError === undefined ? null : (
                    <p className="matrix-cell__error" id={`matrix-error-${environmentId}`}>
                      {liveError}
                    </p>
                  )}
                  <dl className="matrix-editor__provenance">
                    <div>
                      <dt>Updated</dt>
                      <dd>{row.cell?.updated_at === undefined ? 'No published value' : formatTimestamp(row.cell.updated_at)}</dd>
                    </div>
                    <div><dt>Updated by</dt><dd className="mono">{row.cell?.updated_by ?? '—'}</dd></div>
                    <div>
                      <dt>Revision</dt>
                      <dd>{row.signal?.changed_in_revision === undefined ? 'No change signal' : `r${String(row.signal.changed_in_revision)}`}</dd>
                    </div>
                  </dl>
                  <button
                    type="button"
                    className="btn"
                    disabled={busy || applying || (!clearing && !canClearMatrixCell(publishedSet, row.signal?.pending_operation))}
                    onClick={() => {
                      setClears((current) => {
                        const next = new Set(current);
                        if (next.has(environmentId)) next.delete(environmentId);
                        else next.add(environmentId);
                        return next;
                      });
                      setDirty((current) => {
                        const next = new Set(current);
                        next.delete(environmentId);
                        return next;
                      });
                    }}
                  >
                    {clearing ? 'Keep current state' : `Clear ${row.environment.name} to absent`}
                  </button>
                </section>
              );
            })}
          </div>

          {applyError === null ? null : <p className="alert" role="alert">{applyError}</p>}

          <div className="matrix-editor__actions">
            <button
              type="submit"
              className="btn btn--primary"
              disabled={changes.length === 0 || validationByEnvironment.size > 0 || busy || applying}
            >
              {busy || applying ? 'Saving drafts…' : `Save ${String(changes.length)} draft${changes.length === 1 ? '' : 's'}`}
            </button>
            <Link className="btn" to={valuesPath}>Open Values</Link>
            {keyRecord.classification === 'config' && sourceSet ? (
              <button
                type="button"
                className="btn"
                aria-expanded={copyOpen}
                onClick={() => setCopyOpen((open) => !open)}
              >
                {`Copy published ${environment.name} value to…`}
              </button>
            ) : null}
          </div>

          {copyOpen ? (
            <fieldset className="matrix-editor__copy">
              <legend>Copy independent published value to</legend>
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
                    <span>{candidate.name}{protectedEnvironmentIds.includes(candidate.id) ? ' · protected' : ''}</span>
                  </label>
                ))}
              {protectedConfirmationRequired ? (
                <label className="matrix-editor__protected-confirmation">
                  <input
                    type="checkbox"
                    checked={protectedCopyConfirmed}
                    onChange={(event) => setProtectedCopyConfirmed(event.target.checked)}
                  />
                  <span>I confirm copying into protected {protectedDestinationNames.join(', ')}.</span>
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
                disabled={destinations.length === 0 || busy || applying || (protectedConfirmationRequired && !protectedCopyConfirmed)}
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

function validateDeclaration(keyRecord: MatrixKey, value: string): string | null {
  if (value === '') return null;
  const rules = keyRecord.declaration.rule === undefined
    ? keyRecord.declaration.any_of ?? []
    : [keyRecord.declaration.rule];
  const errors = rules.map((rule) => validateMatrixDraft(rule, value));
  return errors.some((error) => error === null)
    ? null
    : errors[0] ?? 'Value does not satisfy the declaration.';
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(value),
  );
}
