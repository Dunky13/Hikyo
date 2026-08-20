import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router';

import { historyHref } from '../api/history.ts';
import {
  matrixPublishValidation,
  matrixMutationError,
  pendingConfigPreview,
  restorePreviewWasAttached,
  useClearMatrixValue,
  useCopyMatrixConfig,
  useMatrixProject,
  usePublishMatrix,
  useReclassifyKey,
  useStageMatrixValue,
  type MatrixKeyList,
  type MatrixPendingDraft,
  type MatrixRef,
  type MatrixSignalCell,
} from '../api/matrix.ts';
import {
  type EnvironmentList,
  type ValueCell,
} from '../api/values.ts';
import { HistoryDrawer } from './HistoryDrawer.tsx';
import type { HistoryCurrentCell } from './history-state.ts';
import {
  MatrixPublishSheet,
  type MatrixPendingEntry,
} from './MatrixPublishSheet.tsx';
import { MatrixRowEditor } from './MatrixRowEditor.tsx';
import { ScanWarnDialog, type ScanWarnItem } from './ScanWarnDialog.tsx';
import {
  computeMatrixProblems,
  groupProblemCounts,
  indexMatrixProblems,
  keysForMatrixFilter,
  normalizeMatrixDraftValue,
  requiredInEnvironment,
  toggleVisibleEnvironment,
  type MatrixFilter,
  type MatrixPresence,
  type MatrixStateKey,
  type MatrixValidationError,
} from './matrix-state.ts';

type MatrixKey = MatrixKeyList['items'][number];
type Environment = EnvironmentList['items'][number];
type Selection = { readonly keyId: string; readonly environmentId?: string };

type DisplayGroup = {
  readonly id: string;
  readonly name: string;
  readonly keys: readonly MatrixKey[];
};

type DisplayRow =
  | { readonly kind: 'group'; readonly group: DisplayGroup }
  | { readonly kind: 'key'; readonly key: MatrixKey };

/**
 * Whole-project environment matrix (#57, frozen prototype iteration 31).
 *
 * The prototype supplies the Cascade geometry and density valves. The flat
 * model supplies the semantics: every cell is set or absent in exactly one
 * environment. No inheritance labels, masks, provenance chains, or ambient
 * cross-environment comparison survive here. Lineage is one gesture away in
 * the row editor as the API's actor, timestamp, and revision facts.
 */
export function Matrix({ historyOpen = false }: { historyOpen?: boolean } = {}) {
  const params = useParams();
  const ref: MatrixRef = { org: params['org'] ?? '', project: params['project'] ?? '' };
  const matrix = useMatrixProject(ref);
  const stage = useStageMatrixValue(ref);
  const clear = useClearMatrixValue(ref);
  const publish = usePublishMatrix(ref);
  const copy = useCopyMatrixConfig(ref);
  const reclassify = useReclassifyKey(ref);

  const environments = matrix.environments.data?.items ?? [];
  const keys = matrix.keys.data?.items ?? [];
  const keyGroups = matrix.groups.data?.items ?? [];
  const [visibleEnvironmentIds, setVisibleEnvironmentIds] = useState<readonly string[]>([]);
  const [collapsedGroups, setCollapsedGroups] = useState<ReadonlySet<string>>(() => new Set());
  const [filter, setFilter] = useState<MatrixFilter>('all');
  const [selection, setSelection] = useState<Selection | null>(null);
  const [warn, setWarn] = useState<{
    readonly keyId: string;
    readonly keyName: string;
    readonly items: readonly ScanWarnItem[];
  } | null>(null);
  const [validationErrors, setValidationErrors] = useState<readonly MatrixValidationError[]>([]);
  const [publishOpen, setPublishOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const matrixScroll = useRef<HTMLDivElement>(null);
  const historyOpener = useRef<HTMLAnchorElement>(null);
  const [mobileLayout, setMobileLayout] = useState(
    () =>
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(max-width: 800px)').matches,
  );

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') {
      return;
    }
    const query = window.matchMedia('(max-width: 800px)');
    const update = () => setMobileLayout(query.matches);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);

  const environmentSignature = environments.map((environment) => environment.id).join('/');
  useEffect(() => {
    setVisibleEnvironmentIds(environments.map((environment) => environment.id));
    setCollapsedGroups(new Set());
    setFilter('all');
    setSelection(null);
  }, [ref.org, ref.project, environmentSignature]);

  const valuesByCell = useMemo(() => {
    const cells = new Map<string, ValueCell>();
    environments.forEach((environment, index) => {
      for (const cell of matrix.values[index]?.data?.items ?? []) {
        cells.set(cellID(cell.key_id, environment.id), cell);
      }
    });
    return cells;
  }, [environments, matrix.values]);

  const signalsByCell = useMemo(() => {
    const cells = new Map<string, MatrixSignalCell>();
    environments.forEach((environment, index) => {
      for (const signal of matrix.signals[index]?.data?.cells ?? []) {
        cells.set(cellID(signal.key_id, environment.id), signal);
      }
    });
    return cells;
  }, [environments, matrix.signals]);

  // The caller's own drafts, keyed by immutable version id. Server truth: the
  // publish sheet and the editors preview from this map, never from anything
  // cached client-side, so a reload or a second browser shows the same review.
  const draftsByVersion = useMemo(() => {
    const drafts = new Map<string, MatrixPendingDraft>();
    for (const query of matrix.pendingDrafts) {
      for (const draft of query.data?.items ?? []) {
        drafts.set(draft.version_id, draft);
      }
    }
    return drafts;
  }, [matrix.pendingDrafts]);

  const stateKeys = useMemo<readonly MatrixStateKey[]>(
    () =>
      keys.map((key) => ({
        id: key.id,
        name: key.name,
        groupId: displayGroupID(key),
        requiredIn: matrixPresence(key),
      })),
    [keys],
  );
  const problems = useMemo(
    () =>
      computeMatrixProblems({
        keys: stateKeys,
        environmentIds: environments.map((environment) => environment.id),
        values: environments.flatMap((environment) =>
          keys.map((key) => ({
            keyId: key.id,
            environmentId: environment.id,
            set: valuesByCell.get(cellID(key.id, environment.id))?.set === true,
            pendingOperation: signalsByCell.get(cellID(key.id, environment.id))?.pending_operation,
          })),
        ),
        validationErrors,
      }),
    [environments, keys, signalsByCell, stateKeys, validationErrors, valuesByCell],
  );
  const problemCounts = useMemo(() => groupProblemCounts(problems), [problems]);
  const problemsByCell = useMemo(() => indexMatrixProblems(problems), [problems]);
  const filteredKeyIDs = useMemo(
    () => new Set(keysForMatrixFilter(stateKeys, problems, filter).map((key) => key.id)),
    [filter, problems, stateKeys],
  );
  const displayGroupList = useMemo(() => displayGroups(keys, keyGroups), [keyGroups, keys]);
  const groups = useMemo(
    () => displayGroupList.map((group) => ({
      ...group,
      keys: group.keys.filter((key) => filteredKeyIDs.has(key.id)),
    })),
    [displayGroupList, filteredKeyIDs],
  );
  const displayRows = useMemo<readonly DisplayRow[]>(
    () =>
      groups.flatMap<DisplayRow>((group) =>
        group.keys.length === 0
          ? []
          : [
              { kind: 'group', group },
              ...(collapsedGroups.has(group.id)
                ? []
                : group.keys.map((key): DisplayRow => ({ kind: 'key', key }))),
            ],
      ),
    [collapsedGroups, groups],
  );
  const groupRowIndexes = useMemo(
    () =>
      new Map(
        displayRows.flatMap((row, index) =>
          row.kind === 'group' ? [[row.group.id, index] as const] : [],
        ),
      ),
    [displayRows],
  );
  const rowVirtualizer = useVirtualizer({
    count: displayRows.length,
    getScrollElement: () => matrixScroll.current,
    estimateSize: (index) => (displayRows[index]?.kind === 'group' ? 44 : 58),
    overscan: 8,
  });
  const visibleEnvironments = environments.filter((environment) =>
    visibleEnvironmentIds.includes(environment.id),
  );
  const firstVisibleEnvironment = visibleEnvironments[0];
  const pendingByEnvironment = useMemo(() => {
    const pending = new Map<string, readonly MatrixPendingEntry[]>();
    environments.forEach((environment, index) => {
      const rows: MatrixPendingEntry[] = [];
      for (const signal of matrix.signals[index]?.data?.cells ?? []) {
        if (signal.pending_version_id !== undefined) {
          if (signal.pending_operation === undefined) {
            throw new Error(
              `matrix signal ${signal.pending_version_id} has no pending_operation`,
            );
          }
          rows.push({
            versionId: signal.pending_version_id,
            keyId: signal.key_id,
            name: signal.name,
            classification: signal.classification,
            operation: signal.pending_operation,
            configPreview: pendingConfigPreview(signal, draftsByVersion),
          });
        }
      }
      pending.set(environment.id, rows);
    });
    return pending;
  }, [environments, matrix.signals, draftsByVersion]);
  const pendingCount = [...pendingByEnvironment.values()].reduce(
    (total, entries) => total + entries.length,
    0,
  );
  const revisionsByEnvironment = useMemo<ReadonlyMap<string, bigint>>(() => {
    const revisions = new Map<string, bigint>();
    environments.forEach((environment, index) => {
      const revision = matrix.signals[index]?.data?.revision;
      if (revision !== undefined) {
        revisions.set(environment.id, revision);
      }
    });
    return revisions;
  }, [environments, matrix.signals]);
  const protectedEnvironmentIds = environments.flatMap((environment, index) =>
    matrix.settings[index]?.data?.protected === true ? [environment.id] : [],
  );
  const pendingCountByEnvironment = useMemo<ReadonlyMap<string, number>>(
    () =>
      new Map(
        [...pendingByEnvironment.entries()].map(([environmentId, entries]) => [
          environmentId,
          entries.length,
        ]),
      ),
    [pendingByEnvironment],
  );
  const pendingByOthersByEnvironment = useMemo<ReadonlyMap<string, number>>(() => {
    const counts = new Map<string, number>();
    environments.forEach((environment, index) => {
      counts.set(
        environment.id,
        (matrix.signals[index]?.data?.cells ?? []).filter((cell) => cell.pending_by_others).length,
      );
    });
    return counts;
  }, [environments, matrix.signals]);
  // The history drawer needs the CURRENT cell state to enumerate the ceremony
  // unit a restore will need: the comparison opens current secret plaintext only
  // where a set secret is being replaced.
  const cellsByEnvironment = useMemo<ReadonlyMap<string, readonly HistoryCurrentCell[]>>(() => {
    const cells = new Map<string, readonly HistoryCurrentCell[]>();
    for (const environment of environments) {
      cells.set(
        environment.id,
        keys.map((key) => ({
          keyId: key.id,
          classification: key.classification,
          set: valuesByCell.get(cellID(key.id, environment.id))?.set === true,
        })),
      );
    }
    return cells;
  }, [environments, keys, valuesByCell]);
  const currentValuesByEnvironment = useMemo<
    ReadonlyMap<string, readonly ValueCell[]>
  >(() => {
    const values = new Map<string, readonly ValueCell[]>();
    environments.forEach((environment, index) => {
      values.set(environment.id, matrix.values[index]?.data?.items ?? []);
    });
    return values;
  }, [environments, matrix.values]);
  const loading =
    matrix.environments.isPending ||
    matrix.keys.isPending ||
    matrix.groups.isPending ||
    matrix.values.some((query) => query.isPending) ||
    matrix.signals.some((query) => query.isPending) ||
    matrix.settings.some((query) => query.isPending) ||
    matrix.pendingDrafts.some((query) => query.isPending);
  const loadError =
    (matrix.environments.isError && matrix.environments.data === undefined) ||
    (matrix.keys.isError && matrix.keys.data === undefined) ||
    (matrix.groups.isError && matrix.groups.data === undefined) ||
    matrix.values.some((query) => query.isError && query.data === undefined) ||
    matrix.signals.some((query) => query.isError && query.data === undefined) ||
    matrix.settings.some((query) => query.isError && query.data === undefined) ||
    matrix.pendingDrafts.some((query) => query.isError && query.data === undefined);
  const backgroundRefreshError =
    (matrix.environments.isError && matrix.environments.data !== undefined) ||
    (matrix.keys.isError && matrix.keys.data !== undefined) ||
    (matrix.groups.isError && matrix.groups.data !== undefined) ||
    matrix.values.some((query) => query.isError && query.data !== undefined) ||
    matrix.signals.some((query) => query.isError && query.data !== undefined) ||
    matrix.settings.some((query) => query.isError && query.data !== undefined);
  const virtualRows = rowVirtualizer.getVirtualItems();
  const virtualPaddingTop = virtualRows[0]?.start ?? 0;
  const virtualPaddingBottom =
    rowVirtualizer.getTotalSize() - (virtualRows[virtualRows.length - 1]?.end ?? 0);

  const clearValidation = (keyId: string, environmentId: string) =>
    setValidationErrors((current) =>
      current.filter(
        (error) => error.keyId !== keyId || error.environmentId !== environmentId,
      ),
    );
  const recordValidation = (keyId: string, environmentId: string, message: string) =>
    setValidationErrors((current) => [
      ...current.filter(
        (error) => error.keyId !== keyId || error.environmentId !== environmentId,
      ),
      { keyId, environmentId, message },
    ]);

  const publishSelected = (selectedEnvironmentIds: readonly string[]) => {
    const addressedEnvironment = selectedEnvironmentIds[0];
    if (addressedEnvironment === undefined) {
      throw new Error('publish action has no selected environment');
    }
    const selectedVersionIds = selectedEnvironmentIds.flatMap((environmentId) =>
      (pendingByEnvironment.get(environmentId) ?? []).map((entry) => entry.versionId),
    );
    if (selectedVersionIds.length === 0) {
      throw new Error('publish action has no selected draft versions');
    }
    publish.mutate(
      {
        addressedEnvironment,
        environmentIds: selectedEnvironmentIds,
        versionIds: selectedVersionIds,
      },
      {
        onSuccess: (result) => {
          setValidationErrors((current) =>
            current.filter(
              (error) => !selectedEnvironmentIds.includes(error.environmentId),
            ),
          );
          const revisions = result.environments.map((published) => {
            const environment = environments.find(
              (candidate) => candidate.id === published.environment_id,
            );
            return `${environment?.name ?? published.environment_id} r${String(published.revision)}`;
          });
          setPublishOpen(false);
          setNotice(`Published atomically: ${revisions.join(', ')}. Signals updated.`);
        },
        onError: (error) => {
          const validation = matrixPublishValidation(error, keys, selectedEnvironmentIds);
          if (validation !== null) {
            recordValidation(
              validation.keyId,
              validation.environmentId,
              validation.message,
            );
          }
        },
      },
    );
  };

  if (loading) {
    return <p role="status">Loading environment matrix…</p>;
  }
  if (loadError) {
    return (
      <p className="alert" role="alert">
        <span className="alert__glyph" aria-hidden="true">!</span>
        <span>The environment matrix could not be loaded. Reload to try again.</span>
      </p>
    );
  }

  const selectedKey = selection === null ? undefined : keys.find((key) => key.id === selection.keyId);
  const selectedEnvironment =
    selection === null
      ? undefined
      : selection.environmentId === undefined
        ? environments[0]
        : environments.find((environment) => environment.id === selection.environmentId);
  return (
    <>
    <section
      className="matrix"
      aria-labelledby="matrix-title"
      inert={historyOpen && mobileLayout}
    >
      <div className="matrix__head">
        <div>
          <h1 id="matrix-title">Environment matrix</h1>
          <p>{`${String(keys.length)} keys across ${String(environments.length)} environments`}</p>
        </div>
        <span className="matrix__head-spacer" />
        <button
          type="button"
          className="btn"
          disabled={pendingCount === 0}
          aria-expanded={publishOpen}
          aria-controls="matrix-publish"
          onClick={() => setPublishOpen((open) => !open)}
        >
          {pendingCount === 0 ? 'No unpublished drafts' : `Δ Review & publish ${String(pendingCount)} draft${pendingCount === 1 ? '' : 's'}`}
        </button>
      </div>

      {notice === null ? null : (
        <p className="notice" role="status">
          <span aria-hidden="true">✓</span>
          <span>{notice}</span>
        </p>
      )}

      {mutationError === null ? null : (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>{mutationError}</span>
        </p>
      )}

      {backgroundRefreshError ? (
        <p className="alert" role="status">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>Live matrix refresh failed. Your loaded data and open edits are preserved; retrying automatically.</span>
        </p>
      ) : null}

      {publishOpen ? (
        <MatrixPublishSheet
          refData={ref}
          environments={environments}
          revisions={revisionsByEnvironment}
          pendingByEnvironment={pendingByEnvironment}
          problems={problems}
          protectedEnvironmentIds={protectedEnvironmentIds}
          busy={publish.isPending}
          mutationError={
            publish.isError
              ? matrixMutationError(
                  publish.error,
                  'publish',
                  restorePreviewWasAttached(publish.error),
                )
              : null
          }
          onPublish={publishSelected}
        />
      ) : null}

      <div className="matrix__layout">
        <nav className="matrix__groups" aria-label="Key groups">
          <h2>Groups</h2>
          {displayGroupList.map((group) => {
            const actuallyHidden =
              filter === 'problems' && group.keys.every((key) => !filteredKeyIDs.has(key.id));
            const count = problemCounts.get(group.id) ?? 0;
            return (
              <button
                type="button"
                className="matrix__group-link"
                key={group.id}
                disabled={actuallyHidden}
                title={actuallyHidden ? 'hidden by the problems filter' : undefined}
                onClick={() => {
                  const index = groupRowIndexes.get(group.id);
                  if (index !== undefined) rowVirtualizer.scrollToIndex(index, { align: 'start' });
                }}
              >
                <span className="mono">{group.name}/</span>
                <span>{String(group.keys.length)}</span>
                {count === 0 ? null : <span className="matrix__count count">! {String(count)}</span>}
              </button>
            );
          })}
          <button
            type="button"
            className="matrix__group-link"
            aria-pressed={filter === 'problems'}
            onClick={() => setFilter((current) => current === 'all' ? 'problems' : 'all')}
          >
            <span>⚠ Problems</span>
            {problems.length === 0 ? null : <span className="matrix__count count">{String(problems.length)}</span>}
          </button>
        </nav>

        <div className="matrix__surface">
          {filter === 'problems' ? (
            <div className="matrix__filter" role="status">
              <span>{`⚠ filter active: problems — showing ${String(filteredKeyIDs.size)} of ${String(keys.length)} keys`}</span>
              <button type="button" className="btn" onClick={() => setFilter('all')}>
                ✕ show all keys
              </button>
            </div>
          ) : null}

          <details className="matrix__environment-picker">
            <summary className="btn">
              {`Environments ${String(visibleEnvironments.length)}/${String(environments.length)}`}
            </summary>
            <fieldset>
              <legend>Visible environments</legend>
              {environments.map((environment) => {
                const checked = visibleEnvironmentIds.includes(environment.id);
                return (
                  <label key={environment.id}>
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={checked && visibleEnvironmentIds.length === 1}
                      onChange={() =>
                        setVisibleEnvironmentIds((current) =>
                          toggleVisibleEnvironment(
                            current,
                            environment.id,
                            environments.map((candidate) => candidate.id),
                          ),
                        )
                      }
                    />
                    <span>{environment.name}</span>
                  </label>
                );
              })}
            </fieldset>
          </details>

          {keys.length === 0 ? (
            <div className="matrix__empty" role="status">
              <h2>No keys yet</h2>
              <p>Declare a key, then give each environment its own explicit value.</p>
            </div>
          ) : filter === 'problems' && filteredKeyIDs.size === 0 ? (
            <div className="matrix__empty" role="status">
              <h2>No problems</h2>
              <p>Every readable environment satisfies its required values.</p>
              <button type="button" className="btn btn--primary" onClick={() => setFilter('all')}>
                Show all keys
              </button>
            </div>
          ) : (
            <div className="matrix__scroll" ref={matrixScroll}>
              <table className="matrix__table">
                <thead>
                  <tr>
                    <th scope="col">Key</th>
                    {visibleEnvironments.map((environment) => {
                      const revision = revisionsByEnvironment.get(environment.id);
                      return (
                        <th scope="col" key={environment.id}>
                          <span>{environment.name}</span>
                          {revision === undefined ? null : (
                            <Link
                              className="btn matrix__history-link"
                              data-history-environment={environment.id}
                              to={historyHref({ ...ref, env: environment.id })}
                              onClick={(event) => {
                                historyOpener.current = event.currentTarget;
                              }}
                            >
                              {`rev ${String(revision)} · history`}
                            </Link>
                          )}
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody>
                  {virtualPaddingTop > 0 ? (
                    <tr aria-hidden="true" className="matrix__virtual-spacer">
                      <td
                        colSpan={visibleEnvironments.length + 1}
                        style={{ height: virtualPaddingTop }}
                      />
                    </tr>
                  ) : null}
                  {virtualRows.map((virtualRow) => {
                    const row = displayRows[virtualRow.index];
                    if (row === undefined) return null;
                    if (row.kind === 'group') {
                      const { group } = row;
                      const collapsed = collapsedGroups.has(group.id);
                      const count = problemCounts.get(group.id) ?? 0;
                      return (
                        <tr
                          className="matrix__group-row"
                          key={`group-${group.id}`}
                          data-index={virtualRow.index}
                          ref={rowVirtualizer.measureElement}
                        >
                          <th colSpan={visibleEnvironments.length + 1}>
                            <button
                              type="button"
                              id={groupDOMID(group.id)}
                              aria-expanded={!collapsed}
                              onClick={() =>
                                setCollapsedGroups((current) => {
                                  const next = new Set(current);
                                  if (next.has(group.id)) next.delete(group.id);
                                  else next.add(group.id);
                                  return next;
                                })
                              }
                            >
                              <span aria-hidden="true">{collapsed ? '▸' : '▾'}</span>
                              <span>{group.name}</span>
                              <span>{String(group.keys.length)}</span>
                              {count === 0 ? null : (
                                <span className="matrix__problem-count count">
                                  {`! ${String(count)} problem${count === 1 ? '' : 's'}`}
                                </span>
                              )}
                              {collapsed ? (
                                <span className="matrix__group-summary mono">
                                  {group.keys.map((key) => key.name).join(', ')}
                                </span>
                              ) : null}
                            </button>
                          </th>
                        </tr>
                      );
                    }
                    const { key } = row;
                    return (
                      <tr
                        key={key.id}
                        data-index={virtualRow.index}
                        ref={rowVirtualizer.measureElement}
                      >
                        <th scope="row" title={key.name}>
                          {/* The key NAME opens its history (revision-history it-1/6:
                              "a key name click opens the same drawer filtered to
                              that key"); any CELL opens the row editor. env-matrix 31
                              wires nothing to the name, so the history lock is the only
                              one that speaks. */}
                          <Link
                            className="matrix__key mono"
                            aria-label={`History of ${key.name}`}
                            to={historyHref({
                              ...ref,
                              ...(firstVisibleEnvironment === undefined
                                ? {}
                                : { env: firstVisibleEnvironment.id }),
                              keyId: key.id,
                            })}
                          >
                            {key.classification === 'secret' ? <span aria-hidden="true">🔒 </span> : null}
                            {key.name}
                          </Link>
                          <span className="matrix__required">{requiredLabel(key, environments)}</span>
                        </th>
                        {visibleEnvironments.map((environment) => {
                          const id = cellID(key.id, environment.id);
                          return (
                            <td key={environment.id}>
                              <MatrixCell
                                cell={valuesByCell.get(id)}
                                keyRecord={key}
                                environment={environment}
                                signal={signalsByCell.get(id)}
                                problems={problemsByCell.get(id) ?? []}
                                onOpen={() =>
                                  setSelection({ keyId: key.id, environmentId: environment.id })
                                }
                              />
                            </td>
                          );
                        })}
                      </tr>
                    );
                  })}
                  {virtualPaddingBottom > 0 ? (
                    <tr aria-hidden="true" className="matrix__virtual-spacer">
                      <td
                        colSpan={visibleEnvironments.length + 1}
                        style={{ height: virtualPaddingBottom }}
                      />
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {selectedKey === undefined || selectedEnvironment === undefined ? null : (
        <MatrixRowEditor
          refData={ref}
          keyRecord={selectedKey}
          environment={selectedEnvironment}
          environments={environments}
          protectedEnvironmentIds={protectedEnvironmentIds}
          rows={environments.map((environment) => {
            const signal = signalsByCell.get(cellID(selectedKey.id, environment.id));
            return {
              environment,
              protected: protectedEnvironmentIds.includes(environment.id),
              cell: valuesByCell.get(cellID(selectedKey.id, environment.id)),
              signal,
              draftPreview: pendingConfigPreview(signal, draftsByVersion),
              problems:
                problemsByCell.get(cellID(selectedKey.id, environment.id)) ?? [],
            };
          })}
          busy={stage.isPending || clear.isPending || copy.isPending}
          mutationError={mutationError}
          onClose={() => setSelection(null)}
          onApply={async (changes) => {
            setMutationError(null);
            let normalizedCount = 0;
            const warnItems: ScanWarnItem[] = [];
            for (const change of changes) {
              try {
                if (change.operation === 'set') {
                  const normalizedValue = normalizeMatrixDraftValue(change.value);
                  if (normalizedValue !== change.value) normalizedCount += 1;
                  const staged = await stage.mutateAsync({
                    environment: change.environmentId,
                    key: selectedKey.name,
                    value: normalizedValue,
                  });
                  // Surface-1 warn (#74): the save succeeded; any findings ride
                  // the response bound to the value that produced them (the
                  // canonical, post-normalization bytes the token dismisses).
                  const environmentName =
                    environments.find((candidate) => candidate.id === change.environmentId)?.name ??
                    change.environmentId;
                  for (const finding of staged.findings ?? []) {
                    warnItems.push({
                      environmentId: change.environmentId,
                      environmentName,
                      value: normalizedValue,
                      finding,
                    });
                  }
                } else {
                  await clear.mutateAsync({
                    environment: change.environmentId,
                    key: selectedKey.name,
                  });
                }
                clearValidation(selectedKey.id, change.environmentId);
              } catch (error) {
                setMutationError(
                  matrixMutationError(
                    error instanceof Error ? error : new Error('matrix mutation failed'),
                    change.operation === 'set' ? 'stage' : 'clear',
                  ),
                );
                throw error;
              }
            }
            setNotice(
              `${String(changes.length)} draft${changes.length === 1 ? '' : 's'} updated for ${selectedKey.name}.${normalizedCount === 0 ? '' : ` Leading and trailing whitespace was removed from ${String(normalizedCount)} value${normalizedCount === 1 ? '' : 's'}.`}`,
            );
            setSelection(null);
            if (warnItems.length > 0) {
              setWarn({ keyId: selectedKey.id, keyName: selectedKey.name, items: warnItems });
            }
          }}
          onCopy={(destinations, confirmProtected) => {
            setMutationError(null);
            copy.mutate(
              {
                sourceEnvironment: selectedEnvironment.id,
                key: selectedKey.name,
                destinationEnvironments: destinations,
                confirmProtected,
              },
              {
                onSuccess: () => {
                  setMutationError(null);
                  setNotice(
                    `${selectedKey.name} copied to ${String(destinations.length)} environment${destinations.length === 1 ? '' : 's'}.`,
                  );
                  setSelection(null);
                },
                onError: (error) => setMutationError(matrixMutationError(error, 'copy')),
              },
            );
          }}
        />
      )}

      {warn === null ? null : (
        <ScanWarnDialog
          keyName={warn.keyName}
          items={warn.items}
          onClose={() => setWarn(null)}
          onReclassify={async () => {
            await reclassify.mutateAsync({ key: warn.keyId, classification: 'secret' });
          }}
          onDismiss={async (item) => {
            const staged = await stage.mutateAsync({
              environment: item.environmentId,
              key: warn.keyName,
              value: item.value,
              acknowledgements:
                item.finding.acknowledgement === undefined
                  ? undefined
                  : [item.finding.acknowledgement],
            });
            return (staged.findings ?? []).map((finding) => ({
              environmentId: item.environmentId,
              environmentName: item.environmentName,
              value: item.value,
              finding,
            }));
          }}
        />
      )}

    </section>

      {historyOpen ? (
        <HistoryDrawer
          refData={ref}
          environments={environments}
          keys={keys}
          currentRevisions={revisionsByEnvironment}
          protectedEnvironmentIds={protectedEnvironmentIds}
          cellsByEnvironment={cellsByEnvironment}
          pendingByEnvironment={pendingCountByEnvironment}
          pendingByOthersByEnvironment={pendingByOthersByEnvironment}
          currentValuesByEnvironment={currentValuesByEnvironment}
          openerRef={historyOpener}
        />
      ) : null}
    </>
  );
}

function MatrixCell({
  cell,
  keyRecord,
  environment,
  signal,
  problems,
  onOpen,
}: {
  cell: ValueCell | undefined;
  keyRecord: MatrixKey;
  environment: Environment;
  signal: MatrixSignalCell | undefined;
  problems: readonly { readonly kind: string; readonly message: string }[];
  onOpen: () => void;
}) {
  const requiredProblem = problems.find((problem) => problem.kind === 'required-absent');
  const validationProblem = problems.find((problem) => problem.kind === 'validation');
  let state = '· absent';
  let stateClass = 'matrix-cell--absent';
  if (requiredProblem !== undefined) {
    state = '! required · absent';
    stateClass = 'matrix-cell--problem';
  } else if (validationProblem !== undefined) {
    state = '✕ value problem';
    stateClass = 'matrix-cell--problem';
  } else if (cell?.set === true && keyRecord.classification === 'secret') {
    state = '🔒 set';
    stateClass = 'matrix-cell--secret';
  } else if (cell?.set === true) {
    state = cell.value ?? 'set';
    stateClass = 'matrix-cell--set';
  }
  const pending = signal?.pending_operation === undefined
    ? null
    : `Δ draft ${signal.pending_operation === 'unset' ? 'clear' : 'set'}`;
  const changed = signal?.changed_in_revision === undefined
    ? null
    : `Δ changed in r${String(signal.changed_in_revision)}`;
  const label = `${keyRecord.name} in ${environment.name}: ${state}${pending === null ? '' : `, ${pending}`}`;

  return (
    <>
      <button type="button" className={`matrix-cell cell-state ${stateClass}`} aria-label={label} onClick={onOpen}>
        <span className="matrix-cell__value">{state}</span>
        {pending === null ? null : <span className="matrix-cell__signal">{pending}</span>}
        {signal?.pending_by_others === true ? (
          <span className="matrix-cell__other">◌ draft by another editor</span>
        ) : null}
        {changed === null ? null : <span className="matrix-cell__signal">{changed}</span>}
        <span className="matrix-cell__edit" aria-hidden="true">✎</span>
      </button>
      {validationProblem === undefined ? null : (
        <span className="matrix-cell__error">{validationProblem.message}</span>
      )}
    </>
  );
}

function cellID(keyId: string, environmentId: string): string {
  return `${keyId}/${environmentId}`;
}

function matrixPresence(key: MatrixKey): MatrixPresence {
  const presence = key.presence.required_in;
  if (presence.mode === 'all') return { mode: 'all' };
  if (presence.mode === 'none') return { mode: 'none' };
  return { mode: 'explicit', environmentIds: presence.environment_ids ?? [] };
}

function displayGroupID(key: MatrixKey): string {
  if (key.group_id !== '') return `group:${key.group_id}`;
  return `folder:${key.folder_path === '' ? 'ungrouped' : key.folder_path}`;
}

function displayGroups(
  keys: readonly MatrixKey[],
  groups: readonly { readonly id: string; readonly name: string }[],
): readonly DisplayGroup[] {
  const names = new Map(groups.map((group) => [`group:${group.id}`, group.name]));
  const result = new Map<string, MatrixKey[]>();
  for (const key of keys) {
    const id = displayGroupID(key);
    const entries = result.get(id) ?? [];
    entries.push(key);
    result.set(id, entries);
  }
  return [...result].map(([id, members]) => ({
    id,
    name: names.get(id) ?? (members[0]?.folder_path || 'ungrouped'),
    keys: members,
  }));
}

function groupDOMID(groupId: string): string {
  return `matrix-group-${groupId.replace(/[^A-Za-z0-9_-]/g, '-')}`;
}

function requiredLabel(key: MatrixKey, environments: readonly Environment[]): string {
  const required = environments.filter((environment) =>
    requiredInEnvironment(matrixPresence(key), environment.id),
  );
  if (required.length === 0) return '';
  if (required.length === environments.length) return 'required · all';
  return `required · ${required.map((environment) => environment.name).join(', ')}`;
}
