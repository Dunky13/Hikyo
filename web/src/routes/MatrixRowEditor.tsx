import { useMemo, useState } from 'react';
import { generatePath, Link } from 'react-router';

import { historyHref } from '../api/history.ts';
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
  matrixDraftChanges,
  validateMatrixDraft,
  type MatrixDraftChange,
} from './matrix-state.ts';
import {
  useProtectedPublishCeremony,
  type ProtectedPublishTarget,
} from './useProtectedPublishCeremony.ts';
import { useModalDialog } from './useModalDialog.ts';

type MatrixKey = MatrixKeyList['items'][number];
type Environment = EnvironmentList['items'][number];

type EditorRow = {
  readonly environmentId: string;
  readonly environment: Environment;
  readonly protected: boolean;
  readonly cell: ValueCell | undefined;
  readonly signal: MatrixSignalCell | undefined;
  readonly draftPreview: string | undefined;
  readonly problems: readonly { readonly message: string }[];
};

export type MatrixEditorChange = MatrixDraftChange;

/** Locked row editor: one independently staged field per readable environment. */
export function MatrixRowEditor({
  refData,
  keyRecord,
  environmentId,
  rows,
  busy,
  mutationError,
  onClose,
  onApply,
  onCopy,
}: {
  refData: MatrixRef;
  keyRecord: MatrixKey;
  environmentId: string;
  rows: readonly EditorRow[];
  busy: boolean;
  mutationError: string | null;
  onClose: () => void;
  onApply: (changes: readonly MatrixEditorChange[]) => Promise<void>;
  onCopy: (destinations: readonly string[], confirmProtected: boolean) => void;
}) {
  const dialog = useModalDialog();
  const initialDrafts = useMemo(
    () =>
      new Map(
        rows.map((row) => [
          row.environmentId,
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
  const protectedEnvironmentIds = rows.flatMap((row) =>
    row.protected ? [row.environmentId] : [],
  );
  const protectedGuard = useProtectedPublishCeremony(refData, [
    environmentId,
    keyRecord.id,
    destinations,
    protectedEnvironmentIds,
  ]);
  const sourceRow = rows.find((row) => row.environmentId === environmentId);
  if (sourceRow === undefined) {
    throw new Error(`matrix editor environment ${environmentId} is not in its keyed rows`);
  }
  const environment = sourceRow.environment;

  const valuesPath = generatePath(surfaceById('values').path, {
    org: refData.org,
    project: refData.project,
    environment: environmentId,
  });
  const sourceSet = sourceRow.cell?.set === true;
  const protectedConfirmationRequired = copyRequiresProtectedConfirmation(
    destinations,
    protectedEnvironmentIds,
  );
  const protectedDestinationNames = rows
    .filter(
      (row) =>
        destinations.includes(row.environmentId) &&
        protectedEnvironmentIds.includes(row.environmentId),
    )
    .map((row) => row.environment.name);

  const validationByEnvironment = new Map<string, ReturnType<typeof validateMatrixDraft>>();
  for (const row of rows) {
    if (!dirty.has(row.environmentId) || clears.has(row.environmentId)) {
      continue;
    }
    const value = drafts.get(row.environmentId) ?? '';
    const error = validateDeclaration(keyRecord, value);
    if (error !== null) {
      validationByEnvironment.set(row.environmentId, error);
    }
  }

  const changes = matrixDraftChanges(
    rows.map((row) => row.environmentId),
    drafts,
    dirty,
    clears,
  );

  const protectedTargets = (): readonly ProtectedPublishTarget[] =>
    destinations
      .filter((environmentId) => protectedEnvironmentIds.includes(environmentId))
      .map((environmentId) => {
        const destination = rows.find((row) => row.environmentId === environmentId);
        if (destination === undefined) {
          throw new Error(`protected copy destination ${environmentId} is not in the matrix`);
        }
        return {
          environmentId,
          environmentName: destination.environment.name,
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
            if (changes.length === 0) return;
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
              <p>One independent draft per readable environment. Untouched fields stay unchanged; a touched empty field stages an explicit empty value.</p>
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
                  setDrafts(new Map(rows.map((row) => [row.environmentId, fillAll])));
                  setDirty(new Set(rows.map((row) => row.environmentId)));
                  setClears(new Set());
                }}
              >
                Fill all
              </button>
            </div>
          </div>

          <div className="matrix-row-editor__rows">
            {rows.map((row) => {
              const rowEnvironmentId = row.environmentId;
              const publishedSet = row.cell?.set === true;
              const clearing = clears.has(rowEnvironmentId);
              const liveValidation = validationByEnvironment.get(rowEnvironmentId) ?? null;
              return (
                <section
                  className={`matrix-row-editor__row${row.protected ? ' matrix-row-editor__row--protected' : ''}`}
                  key={rowEnvironmentId}
                  aria-labelledby={`matrix-row-${rowEnvironmentId}`}
                >
                  <div className="matrix-row-editor__row-head">
                    <h3 id={`matrix-row-${rowEnvironmentId}`}>{row.environment.name}</h3>
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
                  <label htmlFor={`matrix-edit-${rowEnvironmentId}`}>
                    {`${row.environment.name} value`}
                  </label>
                  <textarea
                    id={`matrix-edit-${rowEnvironmentId}`}
                    className="mono matrix-editor__value"
                    rows={keyRecord.declaration.rule?.type === 'json' ? 6 : 2}
                    autoComplete="off"
                    value={clearing ? '' : drafts.get(rowEnvironmentId) ?? ''}
                    placeholder={
                      keyRecord.classification === 'secret'
                        ? publishedSet
                          ? 'Write-only · replace current secret'
                          : 'Write-only · set a new secret'
                        : publishedSet
                          ? 'Edit the explicit value'
                          : 'Touch to stage an explicit value'
                    }
                    aria-invalid={liveValidation?.level === 'error' ? true : undefined}
                    aria-describedby={liveValidation === null ? undefined : `matrix-error-${rowEnvironmentId}`}
                    onChange={(event) => {
                      const next = new Map(drafts);
                      next.set(rowEnvironmentId, event.target.value);
                      setDrafts(next);
                      setDirty((current) => new Set(current).add(rowEnvironmentId));
                      setClears((current) => {
                        const nextClears = new Set(current);
                        nextClears.delete(rowEnvironmentId);
                        return nextClears;
                      });
                    }}
                  />
                  {liveValidation === null ? null : (
                    <p
                      className={liveValidation.level === 'error' ? 'matrix-cell__error' : 'matrix-editor__hint'}
                      id={`matrix-error-${rowEnvironmentId}`}
                    >
                      {liveValidation.message}
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
                        if (next.has(rowEnvironmentId)) next.delete(rowEnvironmentId);
                        else next.add(rowEnvironmentId);
                        return next;
                      });
                      setDirty((current) => {
                        const next = new Set(current);
                        next.delete(rowEnvironmentId);
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
          {mutationError === null ? null : <p className="alert" role="alert">{mutationError}</p>}

          <div className="matrix-editor__actions">
            <button
              type="submit"
              className="btn btn--primary"
              disabled={changes.length === 0 || busy || applying}
            >
              {busy || applying ? 'Saving drafts…' : `Save ${String(changes.length)} draft${changes.length === 1 ? '' : 's'}`}
            </button>
            <Link className="btn" to={valuesPath}>Open Values</Link>
            {/*
              The per-key history entry point. Per-key history is a FILTER over
              the same lineage, so it is the history surface with `key` set —
              never a second surface, and never a second fetch.
            */}
            <Link
              className="btn"
              to={historyHref({ ...refData, env: environment.id, keyId: keyRecord.id })}
            >
              {`History for ${keyRecord.name}`}
            </Link>
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
              {rows
                .filter((row) => row.environmentId !== environmentId)
                .map((row) => (
                  <label key={row.environmentId}>
                    <input
                      type="checkbox"
                      checked={destinations.includes(row.environmentId)}
                      onChange={() => {
                        setDestinations((current) =>
                          current.includes(row.environmentId)
                            ? current.filter((id) => id !== row.environmentId)
                            : [...current, row.environmentId],
                        );
                        setProtectedCopyConfirmed(false);
                      }}
                    />
                    <span>{row.environment.name}{row.protected ? ' · protected' : ''}</span>
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
          key={protectedGuard.requestKey}
          request={protectedGuard.request}
          onAuthorised={protectedGuard.onAuthorised}
          onCancel={protectedGuard.onCancel}
        />
      )}
    </>
  );
}

function validateDeclaration(
  keyRecord: MatrixKey,
  value: string,
): ReturnType<typeof validateMatrixDraft> {
  const rules = keyRecord.declaration.rule === undefined
    ? keyRecord.declaration.any_of ?? []
    : [keyRecord.declaration.rule];
  const errors = rules.map((rule) => validateMatrixDraft(rule, value));
  if (errors.some((error) => error === null)) return null;
  return errors.find((error) => error?.level === 'notice') ?? errors[0] ?? {
    level: 'notice',
    message: 'Full declaration validation runs when publishing.',
  };
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(value),
  );
}
