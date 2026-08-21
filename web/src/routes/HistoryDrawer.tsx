import { useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { exportValues } from '@hikyo/client';
import { zExportedValues } from '@hikyo/zod';
import { useMutation } from '@tanstack/react-query';
import { generatePath, Link, useNavigate, useSearchParams } from 'react-router';

import {
  callerSafeRefusal,
  historyRefusalText,
  revisionNumber,
  useReleaseRevisionPin,
  useRestoreRevision,
  useRevisionDetail,
  useRevisionHistory,
  useRevisionPins,
  useProjectRetention,
  useSetRevisionPin,
  type HistoryRevisionItem,
  type RestoreResult,
  type RevisionPinItem,
} from '../api/history.ts';
import { useServiceAccounts } from '../api/identities.ts';
import { ApiError, parsed } from '../api/client.ts';
import { useTransport, useWorkspaceContext, withRemote } from '../api/transport.tsx';
import {
  matrixMutationError,
  rememberRestorePreview,
  restorePreviewWasAttached,
  usePublishMatrix,
  type MatrixKeyList,
  type MatrixRef,
} from '../api/matrix.ts';
import type { EnvironmentList, EnvRef, ValueCell } from '../api/values.ts';
import { surfaceById } from '../app/navigation.ts';
import { Ceremony } from './Ceremony.tsx';
import {
  defaultPinExpiry,
  historyKeyDisplay,
  pinAction,
  pinCeremonyUnit,
  pinExpiry,
  pinExpiryInstant,
  pinComparedToLatest,
  pinSchemaOverrideOffered,
  relativeAge,
  restoreCeremonyUnit,
  restoreKeyName,
  restorePreviewSummary,
  retentionLine,
  revisionActionGate,
  revisionsForKeyFilter,
  soleKeeperPinIds,
  soleKeeperReleaseConsequences,
  SOLE_KEEPER_RELEASE_BUTTON,
  SOLE_KEEPER_RELEASE_TITLE,
  toHistoryRetention,
  workloadLabel,
  type CeremonyKey,
  type HistoryCurrentCell,
  type HistoryImpactChange,
  type HistoryPin,
  type HistoryRevision,
  type HistorySnapshotKey,
  type PinComparison,
  type RevisionActionGate,
} from './history-state.ts';
import { useProtectedPublishCeremony } from './useProtectedPublishCeremony.ts';
import { useModalDialog } from './useModalDialog.ts';

type Environment = EnvironmentList['items'][number];
type MatrixKey = MatrixKeyList['items'][number];

const zPinComparisonValues = zExportedValues.superRefine((values, context) => {
  values.items.forEach((value, index) => {
    if (value.classification === 'secret' && (value.revealed || value.value !== undefined)) {
      context.addIssue({
        code: 'custom',
        path: ['items', index],
        message: 'pin comparison secret values must remain write-presence only',
      });
    }
    if (value.classification === 'config' && (!value.revealed || value.value === undefined)) {
      context.addIssue({
        code: 'custom',
        path: ['items', index],
        message: 'pin comparison config values must carry plaintext',
      });
    }
  });
});

/**
 * The revision-history drawer (#59, locked prototype `revision-history/6`).
 *
 * The shape is iteration 2's verdict **b**: a slim revision list beside a
 * detail pane, rendered over the matrix rather than instead of it. Below the
 * chrome's 800px breakpoint the two panes become one — list, then detail, with
 * a back affordance — because a 440px drawer split in two is neither.
 *
 * Three properties are the surface's whole point and none of them is decoration:
 *
 *  - **Lineage outlives its payload.** A collected revision keeps its row, its
 *    actor and its changed keys, gains a `payload collected` tag, and loses
 *    restore and pin with the stamped policy named. Nothing is reconstructed.
 *  - **Secrets are write-presence only.** The changed-key list says added /
 *    edited / removed and marks the key 🔒. No value, no length, no digest, no
 *    comparison status reaches this surface for a secret, ever.
 *  - **Restore is not a privileged path.** It stages ordinary drafts; the
 *    matrix's own draft dots appear and the ordinary publish sheet commits
 *    them, carrying the preview token that binds them.
 *
 * **Deferred, by name: the revision-to-revision diff modal.** The prototype
 * offers "diff vs previous" / "diff vs current"; no API computes a rev↔rev diff
 * (`diffValues` compares two ENVIRONMENTS), and neither C5 nor S3 names one. The
 * restore impact preview is this surface's "what would change" view.
 */
export function HistoryDrawer({
  refData,
  environments,
  keys,
  currentRevisions,
  protectedEnvironmentIds,
  cellsByEnvironment,
  pendingByEnvironment,
  pendingByOthersByEnvironment,
  currentValuesByEnvironment,
  openerRef,
}: {
  refData: MatrixRef;
  environments: readonly Environment[];
  keys: readonly MatrixKey[];
  currentRevisions: ReadonlyMap<string, bigint>;
  protectedEnvironmentIds: readonly string[];
  cellsByEnvironment: ReadonlyMap<string, readonly HistoryCurrentCell[]>;
  pendingByEnvironment: ReadonlyMap<string, number>;
  pendingByOthersByEnvironment: ReadonlyMap<string, number>;
  currentValuesByEnvironment: ReadonlyMap<string, readonly ValueCell[]>;
  openerRef: RefObject<HTMLAnchorElement | null>;
}) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const fallbackEnvironment = environments[0]?.id ?? '';
  const requested = params.get('env') ?? '';
  const environmentId = environments.some((candidate) => candidate.id === requested)
    ? requested
    : fallbackEnvironment;
  const environment = environments.find((candidate) => candidate.id === environmentId);
  const keyFilter = params.get('key');
  const env = { ...refData, environment: environmentId };

  const transport = useTransport();
  const workspace = useWorkspaceContext();
  const history = useRevisionHistory(env);
  const pins = useRevisionPins(env);
  const retention = useProjectRetention(refData);
  const accounts = useServiceAccounts(refData);
  const restore = useRestoreRevision(env);
  const setPin = useSetRevisionPin(env);
  const releasePin = useReleaseRevisionPin(env);
  const publish = usePublishMatrix(refData);
  const comparePin = useMutation({
    mutationFn: (input: { readonly environmentId: string; readonly revision: bigint }) =>
      parsed(
        exportValues({
          path: { ...refData, environment: input.environmentId },
          body: { revision: revisionNumber(input.revision), reveal: false },
          ...transport,
        }),
        zPinComparisonValues,
      ),
  });
  const guard = useProtectedPublishCeremony(refData);

  const [sheet, setSheet] = useState<Sheet | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [mobileDetail, setMobileDetail] = useState(false);
  const drawerHeading = useRef<HTMLHeadingElement>(null);
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const selectedRow = useRef<HTMLButtonElement>(null);
  const currentEnvironment = useRef(environmentId);
  currentEnvironment.current = environmentId;

  // The clock is read once per mount rather than per row: a timeline
  // whose rows disagree about "now" by a few milliseconds can render two
  // different expiry tiers for the same instant.
  const [now] = useState(() => new Date());

  const revisions = useMemo<readonly HistoryRevision[]>(
    () => (history.data?.items ?? []).map(toHistoryRevision),
    [history.data],
  );
  const filtered = useMemo(
    () => revisionsForKeyFilter(revisions, keyFilter),
    [keyFilter, revisions],
  );
  const currentRevision = currentRevisions.get(environmentId) ?? 0n;
  const requestedRevision = params.get('rev');
  const selected =
    filtered.find((entry) => String(entry.revision) === requestedRevision) ?? filtered[0];
  const keyDisplay =
    keyFilter === null || !history.isSuccess
      ? null
      : historyKeyDisplay(keyFilter, keys, selected);

  const pinRows = useMemo<readonly HistoryPin[]>(
    () => (pins.data?.items ?? []).map(toHistoryPin),
    [pins.data],
  );
  const soleKeepers = useMemo(
    () =>
      retention.data === undefined
        ? new Set<string>()
        : soleKeeperPinIds({
            pins: pinRows,
            revisions,
            policy: toHistoryRetention({
              mode: retention.data.mode,
              ...(retention.data.max_age_seconds == null
                ? {}
                : { max_age_seconds: retention.data.max_age_seconds }),
              ...(retention.data.last_revisions == null
                ? {}
                : { last_revisions: retention.data.last_revisions }),
            }),
            now,
          }),
    [now, pinRows, retention.data, revisions],
  );

  const workloads = (accounts.data?.items ?? []).filter((account) => account.kind === 'workload');
  // A pin binds a WORKLOAD, and a workload does resolve to a name — through the
  // project's service accounts. (A human publisher does not: nothing in this
  // API maps a human principal id to a display name, so those stay ids.)
  const workloadNames = new Map(
    (accounts.data?.items ?? []).map((account) => [account.principal_id, account.name]),
  );
  const selectedGate =
    selected === undefined ? null : revisionActionGate(selected, currentRevision);

  const setParam = (name: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null) {
      next.delete(name);
    } else {
      next.set(name, value);
    }
    setParams(next, { replace: true });
  };

  // Back into the matrix, keeping the workspace: closing the drawer inside a
  // workspace must land on the remote's matrix, not this instance's (#71).
  const matrixPath = withRemote(
    generatePath(surfaceById('matrix').path, refData),
    workspace?.remote ?? '',
  );

  useEffect(() => {
    setSheet(null);
    setOutcome(null);
    setRefusal(null);
  }, [environmentId, keyFilter]);

  useEffect(() => {
    // Snapshot the opener at MOUNT: the matrix stays interactive behind a desktop
    // drawer, so a later click can re-point the shared ref, and close must return
    // focus to the element that actually opened this drawer, not the last one
    // touched. The current-environment link is the fallback when that element
    // is gone (an environment hidden, a re-render that replaced the header).
    const opener = openerRef.current;
    drawerHeading.current?.focus();
    return () => {
      requestAnimationFrame(() => {
        if (opener?.isConnected === true) {
          opener.focus();
          return;
        }
        Array.from(document.querySelectorAll<HTMLAnchorElement>('.matrix__history-link'))
          .find((link) => link.dataset['historyEnvironment'] === currentEnvironment.current)
          ?.focus();
      });
    };
  }, [openerRef]);

  useEffect(() => {
    if (mobileDetail) {
      detailHeading.current?.focus();
    }
  }, [mobileDetail, selected?.revision]);

  if (environment === undefined) {
    return null;
  }

  const secretByKeyId = new Map(keys.map((key) => [key.id, key.classification === 'secret']));

  /** Runs the disclosure ceremony for `unit` when the guard needs one, then acts. */
  const withCeremony = (
    unit: readonly CeremonyKey[],
    purpose: 'restore' | 'pin',
    act: () => void,
  ) => {
    setRefusal(null);
    if (unit.length === 0) {
      act();
      return;
    }
    void guard.run(
      [
        {
          environmentId: environment.id,
          environmentName: environment.name,
          keys: [...unit],
          purpose,
        },
      ],
      act,
      'The disclosure guard could not be read, so nothing was staged',
    );
  };

  const runRestore = (revision: bigint, keyId: string | null, keyName: string | null) => {
    const unit = restoreCeremonyUnit({
      revisionKeys: sheetRevisionKeys(sheet),
      currentCells: cellsByEnvironment.get(environment.id) ?? [],
      keyId,
    });
    withCeremony(unit, 'restore', () => {
      restore.mutate(
        keyName === null ? { revision } : { revision, key: keyName },
        {
          onSuccess: (result) => {
            rememberRestorePreview(
              refData,
              result.changes.map((change) => change.version_id),
              result.preview.token,
            );
            setSheet({
              kind: 'restore',
              revision,
              keyId,
              keyName,
              keys: sheetRevisionKeys(sheet),
              result: {
                changes: result.changes,
                preview: { environments: result.preview.environments },
              },
            });
            setOutcome(
              `Staged ${String(result.changes.length)} draft${result.changes.length === 1 ? '' : 's'} from r${String(revision)} — nothing is published yet.`,
            );
          },
          onError: (error) =>
            setRefusal(historyMutationRefusal(error, 'restore', unit, environment.name)),
        },
      );
    });
  };

  const runPin = (input: {
    readonly revision: bigint;
    readonly workloadPrincipalID: string;
    readonly expiresAt: string;
    readonly overrideSchema: boolean;
    readonly revisionKeys: readonly HistorySnapshotKey[];
  }) => {
    const historical = input.revision !== currentRevision;
    const unit = historical
      ? pinCeremonyUnit(input.revisionKeys, cellsByEnvironment.get(environment.id) ?? [])
      : [];
    withCeremony(unit, 'pin', () => {
      setPin.mutate(
        {
          workloadPrincipalID: input.workloadPrincipalID,
          revision: input.revision,
          expiresAt: pinExpiryInstant(input.expiresAt),
          overrideSchema: input.overrideSchema,
        },
        {
          onSuccess: (result) => {
            setSheet(null);
            // The verb is the SERVER's (`RevisionPinResult.action`), not the
            // label the sheet guessed: created, reassigned and renewed are the
            // locked taxonomy, and the outcome reports what happened.
            setOutcome(
              `Pin ${result.action}: r${String(result.pin.revision)} for ${
                workloadLabel(result.pin.workload_principal_id, workloadNames)
              }, expiring ${result.pin.expires_at.slice(0, 10)}.`,
            );
          },
          onError: (error) => {
            setRefusal(historyMutationRefusal(error, 'pin', unit, environment.name));
            setSheet((current) =>
              current !== null && current.kind === 'pin'
                ? {
                    ...current,
                    offerOverride: pinSchemaOverrideOffered(
                      error instanceof ApiError ? error.detail : undefined,
                    ),
                  }
                : current,
            );
          },
        },
      );
    });
  };

  const publishRestore = (revision: bigint, result: RestoreSheetResult) => {
    const versionIds = result.changes.map((change) => change.version_id);
    const act = () => {
      setRefusal(null);
      publish.mutate(
        {
          addressedEnvironment: environment.id,
          environmentIds: [environment.id],
          versionIds,
        },
        {
          onSuccess: (published) => {
            const target = published.environments.find(
              (entry) => entry.environment_id === environment.id,
            );
            if (target === undefined) {
              throw new Error(`restore publish returned no revision for ${environment.id}`);
            }
            setSheet(null);
            setOutcome(
              `Published the restore from r${String(revision)} as ${environment.name} r${String(target.revision)}.`,
            );
          },
          onError: (error) =>
            setRefusal(
              matrixMutationError(error, 'publish', restorePreviewWasAttached(error)),
            ),
        },
      );
    };
    if (!protectedEnvironmentIds.includes(environment.id)) {
      act();
      return;
    }
    void guard.run(
      [
        {
          environmentId: environment.id,
          environmentName: environment.name,
          keys: result.changes.map((change) => ({ id: change.key_id, name: change.name })),
          purpose: 'publish',
        },
      ],
      act,
      'The protected publish guard could not be read, so nothing was published',
    );
  };

  const runRelease = (pin: HistoryPin) => {
    setRefusal(null);
    releasePin.mutate(pin.workloadPrincipalId, {
      onSuccess: () => {
        setSheet(null);
        setOutcome(
          soleKeepers.has(pin.id)
            ? `Pin released. ${soleKeeperReleaseConsequences(pin.revision)} The workload resumes latest on its next fetch.`
            : `Pin released — the workload resumes latest (r${String(currentRevision)}) on its next fetch. r${String(pin.revision)}'s values stay inside the retention window.`,
        );
      },
      onError: (error) => setRefusal(historyRefusalText(error, 'release')),
    });
  };

  const stagedByMe = pendingByEnvironment.get(environment.id) ?? 0;
  const stagedByOthers = pendingByOthersByEnvironment.get(environment.id) ?? 0;
  const line = retention.data === undefined
    ? null
    : retentionLine({
        inherited: retention.data.inherited,
        ...toHistoryRetention({
          mode: retention.data.mode,
          ...(retention.data.max_age_seconds == null
            ? {}
            : { max_age_seconds: retention.data.max_age_seconds }),
          ...(retention.data.last_revisions == null
            ? {}
            : { last_revisions: retention.data.last_revisions }),
        }),
      });

  return (
    <>
      <aside
        className={`history${mobileDetail ? ' history--detail' : ''}`}
        aria-label="Revision history"
        onKeyDown={(event) => {
          if (event.key === 'Escape' && sheet === null) {
            event.preventDefault();
            void navigate(matrixPath);
          }
        }}
      >
        <div className="history__head">
          <div className="history__title">
            <h2 id="history-title" ref={drawerHeading} tabIndex={-1}>↺ Revision history</h2>
            <span className="history__current count">{`current r${String(currentRevision)}`}</span>
            {protectedEnvironmentIds.includes(environment.id) ? (
              <span className="history__protected">PROTECTED</span>
            ) : null}
            <Link id="history-close" className="btn history__close" to={matrixPath} aria-label="Close revision history">
              ✕ Close
            </Link>
          </div>

          {/*
            Plain toggle buttons, deliberately NOT `role="tab"`. These do not
            switch a panel inside the page — they rewrite the URL the whole
            surface is addressed by, and a tab role would promise keyboard
            semantics (arrow-key roving, an owned tabpanel) that a set of links
            to different states does not have.
          */}
          <div className="history__tabs">
            {environments.map((candidate) => (
              <button
                key={candidate.id}
                type="button"
                className="btn history__tab"
                aria-pressed={candidate.id === environment.id}
                onClick={() => {
                  const next = new URLSearchParams(params);
                  next.set('env', candidate.id);
                  next.delete('rev');
                  setParams(next, { replace: true });
                  setMobileDetail(false);
                }}
              >
                {candidate.name}
              </button>
            ))}
          </div>

          {stagedByMe === 0 && stagedByOthers === 0 ? null : (
            <p className="history__pending" role="status">
              {stagedByMe === 0
                ? ''
                : `${String(stagedByMe)} staged by you (unpublished)`}
              {stagedByMe > 0 && stagedByOthers > 0 ? ' · ' : ''}
              {stagedByOthers === 0
                ? ''
                : `${String(stagedByOthers)} pending by other people`}
            </p>
          )}

          {line === null ? null : (
            <p className="history__retention">
              <span>{line.window}</span>
              <span className="history__badge" title={line.badgeTitle}>
                {line.badge}
              </span>
              <span className="history__settings-pointer">
                → change it in project settings › Policy
              </span>
            </p>
          )}

          {keyFilter === null ? null : (
            <p className="history__filter" role="status">
              <span>{`⚠ filter active: history of ${keyDisplay?.label ?? keyFilter} — showing ${String(filtered.length)} of ${String(revisions.length)} revisions`}</span>
              <button type="button" className="btn" onClick={() => setParam('key', null)}>
                ✕ show every revision
              </button>
            </p>
          )}
        </div>

        {outcome === null ? null : (
          <p className="notice" role="status">
            <span aria-hidden="true">✓</span>
            <span>{outcome}</span>
          </p>
        )}
        {refusal === null && guard.error === null ? null : (
          <p id="history-drawer-refusal" className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">!</span>
            <span>{refusal ?? guard.error}</span>
          </p>
        )}
        {retention.isError ? (
          <p id="history-retention-error" className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">!</span>
            <span>Retention policy could not be read. Pin release is disabled until it succeeds.</span>
          </p>
        ) : null}

        {history.isPending ? (
          <p role="status">Loading revision history…</p>
        ) : history.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">!</span>
            <span>The revision history could not be read. Reload to try again.</span>
          </p>
        ) : filtered.length === 0 ? (
          <p className="history__empty" role="status">
            {keyFilter === null
              ? 'No revisions published in this environment yet.'
              : `No revision has moved ${keyDisplay?.label ?? keyFilter} in this environment.`}
          </p>
        ) : (
          <div className="history__panes">
            <ol className="history__list" aria-label="Revisions, newest first">
              {filtered.map((entry) => {
                const pinnedHere = pinRows.filter((pin) => pin.revision === entry.revision);
                return (
                  <li key={String(entry.revision)}>
                    <button
                      data-history-revision={String(entry.revision)}
                      ref={entry.revision === selected?.revision ? selectedRow : undefined}
                      type="button"
                      className="btn history__row"
                      aria-current={entry.revision === selected?.revision}
                      onClick={() => {
                        setParam('rev', String(entry.revision));
                        setMobileDetail(true);
                      }}
                    >
                      <span className="mono">{`r${String(entry.revision)}`}</span>
                      {entry.revision === currentRevision ? (
                        <span className="history__tag">current</span>
                      ) : null}
                      {pinnedHere.length === 0 ? null : (
                        <span className="history__tag" title={`pinned by ${String(pinnedHere.length)} workload(s)`}>
                          ⚲ pinned
                        </span>
                      )}
                      {entry.payloadPresent ? null : (
                        <span className="history__tag history__tag--collected">payload collected</span>
                      )}
                      <span className="history__age">{relativeAge(entry.publishedAt, now)}</span>
                    </button>
                  </li>
                );
              })}
            </ol>

            <div className="history__detail">
              <button
                id="history-detail-back"
                type="button"
                className="btn history__back"
                onClick={() => {
                  setMobileDetail(false);
                  requestAnimationFrame(() => selectedRow.current?.focus());
                }}
              >
                ← All revisions
              </button>
              {selected === undefined || selectedGate === null ? null : (
                <RevisionDetail
                  env={env}
                  revision={selected}
                  revisions={revisions}
                  headingRef={detailHeading}
                  gate={selectedGate}
                  currentRevision={currentRevision}
                  pins={pinRows}
                  workloadNames={workloadNames}
                  soleKeepers={soleKeepers}
                  releaseAvailable={retention.isSuccess}
                  releaseUnavailableReason={
                    retention.isError
                      ? 'Release disabled: retention policy could not be read.'
                      : 'Release disabled until the retention policy has loaded.'
                  }
                  secretByKeyId={secretByKeyId}
                  now={now}
                  keyFilter={keyFilter}
                  onFilterKey={(keyId) => {
                    setParam('key', keyId);
                    // "Show me this key's history" answers with a LIST, so the
                    // phone's single pane goes back to it. On a desktop both
                    // panes are on screen and this changes nothing.
                    setMobileDetail(false);
                    requestAnimationFrame(() => selectedRow.current?.focus());
                  }}
                  onRestore={(revisionKeys, keyId) => {
                    setRefusal(null);
                    let keyName: string | null = null;
                    if (keyId !== null) {
                      try {
                        keyName = restoreKeyName(keyId, keys, selected);
                      } catch (error) {
                        if (!(error instanceof Error)) {
                          throw error;
                        }
                        setRefusal(error.message);
                        return;
                      }
                    }
                    setSheet({
                      kind: 'restore',
                      revision: selected.revision,
                      keyId,
                      keyName,
                      keys: revisionKeys,
                      result: null,
                    });
                  }}
                  onPin={(revisionKeys) => {
                    setRefusal(null);
                    setSheet({
                      kind: 'pin',
                      revision: selected.revision,
                      keys: revisionKeys,
                      workloadPrincipalID: workloads[0]?.principal_id ?? '',
                      expiresAt: defaultPinExpiry(now),
                      overrideSchema: false,
                      offerOverride: false,
                    })
                  }}
                  onRelease={(pin) => {
                    setRefusal(null);
                    if (soleKeepers.has(pin.id)) {
                      setSheet({ kind: 'release', pin });
                    } else {
                      runRelease(pin);
                    }
                  }}
                />
              )}
            </div>
          </div>
        )}
      </aside>

      {sheet?.kind === 'restore' ? (
        <RestoreSheet
          environmentName={environment.name}
          revision={sheet.revision}
          keyName={sheet.keyName}
          result={sheet.result}
          busy={restore.isPending}
          publishBusy={publish.isPending}
          refusal={refusal ?? guard.error}
          matrixPath={matrixPath}
          onStage={() => runRestore(sheet.revision, sheet.keyId, sheet.keyName)}
          onPublish={() => {
            if (sheet.result === null) {
              throw new Error('restore publish started without a staged result');
            }
            publishRestore(sheet.revision, sheet.result);
          }}
          onClose={() => setSheet(null)}
        />
      ) : null}

      {sheet?.kind === 'pin' ? (
        <PinSheet
          environmentName={environment.name}
          revision={sheet.revision}
          isCurrent={sheet.revision === currentRevision}
          currentRevision={currentRevision}
          soleKeepers={soleKeepers}
          retentionReady={retention.isSuccess}
          workloads={workloads.map((account) => ({
            principalID: account.principal_id,
            name: account.name,
            pinnedRevision: pinRows.find((pin) => pin.workloadPrincipalId === account.principal_id)
              ?.revision,
            pinID: pinRows.find((pin) => pin.workloadPrincipalId === account.principal_id)?.id,
          }))}
          state={sheet}
          busy={setPin.isPending}
          refusal={refusal ?? guard.error}
          comparisonBusy={comparePin.isPending}
          comparisonError={
            comparePin.isError &&
            comparePin.variables.environmentId === environment.id &&
            comparePin.variables.revision === sheet.revision
              ? comparisonRefusal(comparePin.error, sheet.revision)
              : null
          }
          comparison={
            comparePin.isSuccess &&
            comparePin.variables.environmentId === environment.id &&
            comparePin.variables.revision === sheet.revision
              ? pinComparedToLatest({
                  revision: sheet.revision,
                  revisionKeys: sheet.keys,
                  historical: comparePin.data.items,
                  latest: (currentValuesByEnvironment.get(environment.id) ?? []).map((value) => ({
                    keyId: value.key_id,
                    name: value.name,
                    classification: value.classification,
                    set: value.set,
                    revealed: value.revealed,
                    ...(value.value === undefined ? {} : { value: value.value }),
                  })),
                  laterRevisions: revisions.filter(
                    (revision) => revision.revision > sheet.revision,
                  ),
                })
              : null
          }
          onCompare={() => comparePin.mutate({ environmentId: environment.id, revision: sheet.revision })}
          onChange={(next) => setSheet({ ...sheet, ...next })}
          onSubmit={() =>
            runPin({
              revision: sheet.revision,
              workloadPrincipalID: sheet.workloadPrincipalID,
              expiresAt: sheet.expiresAt,
              overrideSchema: sheet.overrideSchema,
              revisionKeys: sheet.keys,
            })
          }
          onClose={() => setSheet(null)}
        />
      ) : null}

      {sheet?.kind === 'release' ? (
        <ReleaseSheet
          pin={sheet.pin}
          currentRevision={currentRevision}
          workloadName={
            workloadLabel(sheet.pin.workloadPrincipalId, workloadNames)
          }
          busy={releasePin.isPending}
          releaseAllowed={retention.isSuccess}
          onRelease={() => runRelease(sheet.pin)}
          onClose={() => setSheet(null)}
        />
      ) : null}

      {guard.request === null ? null : (
        <Ceremony
          request={guard.request}
          onAuthorised={guard.onAuthorised}
          onCancel={guard.onCancel}
        />
      )}
    </>
  );
}

type Sheet =
  | {
      readonly kind: 'restore';
      readonly revision: bigint;
      readonly keyId: string | null;
      readonly keyName: string | null;
      readonly keys: readonly HistorySnapshotKey[];
      readonly result: RestoreSheetResult | null;
    }
  | {
      readonly kind: 'pin';
      readonly revision: bigint;
      readonly keys: readonly HistorySnapshotKey[];
      readonly workloadPrincipalID: string;
      readonly expiresAt: string;
      readonly overrideSchema: boolean;
      readonly offerOverride: boolean;
    }
  | { readonly kind: 'release'; readonly pin: HistoryPin };

type RestoreSheetResult = {
  readonly changes: RestoreResult['changes'];
  readonly preview: {
    readonly environments: RestoreResult['preview']['environments'];
  };
};

function sheetRevisionKeys(sheet: Sheet | null): readonly HistorySnapshotKey[] {
  return sheet !== null && sheet.kind !== 'release' ? sheet.keys : [];
}

/**
 * The detail pane: one revision's lineage, its consumers, and its two actions.
 *
 * The delivered key set comes from `getRevision`, which is NOT fetched for a
 * collected revision — that endpoint derives a change token over the snapshot's
 * manifest and refuses a collected payload by name. The changed-key list below
 * is lineage and survives collection either way.
 */
function RevisionDetail({
  env,
  revision,
  revisions,
  headingRef,
  gate,
  currentRevision,
  pins,
  workloadNames,
  soleKeepers,
  releaseAvailable,
  releaseUnavailableReason,
  secretByKeyId,
  now,
  keyFilter,
  onFilterKey,
  onRestore,
  onPin,
  onRelease,
}: {
  env: EnvRef;
  revision: HistoryRevision;
  revisions: readonly HistoryRevision[];
  headingRef: RefObject<HTMLHeadingElement | null>;
  gate: RevisionActionGate;
  currentRevision: bigint;
  pins: readonly HistoryPin[];
  workloadNames: ReadonlyMap<string, string>;
  soleKeepers: ReadonlySet<string>;
  releaseAvailable: boolean;
  releaseUnavailableReason: string;
  secretByKeyId: ReadonlyMap<string, boolean>;
  now: Date;
  keyFilter: string | null;
  onFilterKey: (keyId: string) => void;
  onRestore: (revisionKeys: readonly HistorySnapshotKey[], keyId: string | null) => void;
  onPin: (revisionKeys: readonly HistorySnapshotKey[]) => void;
  onRelease: (pin: HistoryPin) => void;
}) {
  const detail = useRevisionDetail(env, revision.revision, revision.payloadPresent);
  const revisionKeys: readonly HistorySnapshotKey[] = (detail.data?.keys ?? []).map((key) => ({
    keyId: key.key_id,
    name: key.name,
    classification: key.classification,
  }));
  const pinnedHere = pins.filter((pin) => pin.revision === revision.revision);

  return (
    <section aria-labelledby="history-detail-title">
      <h3 id="history-detail-title" className="mono" ref={headingRef} tabIndex={-1}>
        {`r${String(revision.revision)}`}
        {revision.revision === currentRevision ? <span className="history__tag">current</span> : null}
        {revision.payloadPresent ? null : (
          <span className="history__tag history__tag--collected">payload collected</span>
        )}
      </h3>
      <dl className="history__meta">
        <div>
          <dt>Published by</dt>
          {/*
            Principal IDS, not names. Nothing in this API resolves a HUMAN
            principal id to a display name — there is no member-listing
            operation, and inventing one is a permission decision this ticket
            does not own — so the row shows a shortened id and carries the whole
            one in `title`. Workloads DO resolve, through the project's service
            accounts, which is why the pin rows below name them.
          */}
          <dd className="mono" title={revision.publishedBy}>
            {shortPrincipal(revision.publishedBy)}
          </dd>
        </div>
        <div>
          <dt>Published</dt>
          <dd>
            <time dateTime={revision.publishedAt}>{relativeAge(revision.publishedAt, now)}</time>
          </dd>
        </div>
        <div>
          <dt>Schema revision pinned</dt>
          <dd className="mono">{`s${String(revision.schemaRevision)}`}</dd>
        </div>
      </dl>

      {pinnedHere.length === 0 ? null : (
        <p className="history__consumers">
          {`⚲ ${pinnedHere
            .map((pin) => workloadLabel(pin.workloadPrincipalId, workloadNames))
            .join(', ')} receive${pinnedHere.length === 1 ? 's' : ''} this revision's values`}
          {revision.revision === currentRevision ? '' : ` instead of latest (r${String(currentRevision)})`}
          {' — until the pin is released or expires.'}
        </p>
      )}

      {gate.reason === null ? null : (
        <p className="history__gate" role="status">
          {gate.reason}
        </p>
      )}
      {detail.isError ? (
        <p id="history-detail-error" className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>{revisionDetailRefusal(detail.error, revision.revision)}</span>
        </p>
      ) : null}

      <h4>{`Changed keys (${String(revision.changedKeys.length)})`}</h4>
      <ul className="history__changes">
        {revision.changedKeys.map((changed) => {
          const secret = secretByKeyId.get(changed.keyId) === true;
          return (
            <li key={changed.keyId}>
              <button
                type="button"
                className="btn history__change mono"
                aria-pressed={keyFilter === changed.keyId}
                onClick={() => onFilterKey(changed.keyId)}
              >
                {secret ? <span aria-hidden="true">🔒 </span> : null}
                {changed.name}
              </button>
              <span className="history__kind">{changed.change}</span>
              {secret ? <span className="history__presence">write-presence only</span> : null}
              <button
                type="button"
                className="btn"
                disabled={!gate.restore || !detail.isSuccess}
                onClick={() => onRestore(revisionKeys, changed.keyId)}
              >
                {`Restore ${changed.name}…`}
              </button>
            </li>
          );
        })}
      </ul>

      <div className="history__actions">
        <button
          type="button"
          className="btn btn--primary"
          disabled={!gate.restore || !detail.isSuccess}
          title={gate.restore ? undefined : gate.reason ?? undefined}
          onClick={() => onRestore(revisionKeys, null)}
        >
          {`Restore r${String(revision.revision)}…`}
        </button>
        <button
          type="button"
          className="btn"
          disabled={!gate.pin || !detail.isSuccess}
          title={gate.pin ? undefined : gate.reason ?? undefined}
          onClick={() => onPin(revisionKeys)}
        >
          {`Pin r${String(revision.revision)}…`}
        </button>
      </div>

      <h4>{`Pins (${String(pins.length)})`}</h4>
      <p className="history__pin-note">
        A pinned workload stops following latest — it keeps receiving exactly the pinned
        revision&apos;s values, restarts included, until the pin is released or expires.
      </p>
      {releaseAvailable ? null : (
        <p
          id="history-release-disabled"
          className="history__gate"
          role={releaseUnavailableReason.includes('could not') ? 'alert' : 'status'}
        >
          {releaseUnavailableReason}
        </p>
      )}
      {pins.length === 0 ? (
        <p className="history__empty">{`No pins — every workload here follows latest (r${String(currentRevision)}).`}</p>
      ) : (
        <ul className="history__pins">
          {pins.map((pin) => {
            const expiry = pinExpiry(pin.expiresAt, now);
            const sole = soleKeepers.has(pin.id);
            const workload = workloadLabel(pin.workloadPrincipalId, workloadNames);
            const publishesBehind = revisions.filter(
              (entry) => entry.revision > pin.revision,
            ).length;
            const gap = pin.revision === currentRevision
              ? `${workload} is pinned to the current revision r${String(pin.revision)} — it will keep these values when the next publish lands.`
              : `${workload} still runs on r${String(pin.revision)}'s values — ${String(publishesBehind)} publishes behind latest (r${String(currentRevision)}). New publishes don't reach it.`;
            return (
              <li key={pin.id} className="history__pin">
                <span className="mono">{`⚲ r${String(pin.revision)}`}</span>
                <span className="mono" title={pin.workloadPrincipalId}>
                  {workload}
                </span>
                <span className={`history__expiry history__expiry--${expiry.tier}`}>
                  {expiry.tier === 'expired'
                    ? `expired — still delivering r${String(pin.revision)} while its payload survives`
                    : expiry.text}
                </span>
                <span className="history__pin-gap">{gap}</span>
                {sole ? (
                  <span
                    className="history__warn"
                    title={soleKeeperReleaseConsequences(pin.revision)}
                  >
                    ⚠ sole keeper
                  </span>
                ) : null}
                {pin.schemaOverride ? (
                  <span className="history__warn" title="Pinned despite a current-schema failure, recorded as an explicit override. Pinned delivery is verbatim.">
                    Δ schema drift
                  </span>
                ) : null}
                <button
                  type="button"
                  className="btn"
                  disabled={!releaseAvailable}
                  aria-describedby={releaseAvailable ? undefined : 'history-release-disabled'}
                  onClick={() => onRelease(pin)}
                >
                  Release
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/**
 * The restore sheet: what a restore does, then what it did.
 *
 * **Divergence from the prototype, named.** Iteration 1 previews first and
 * stages on confirmation. The shipped verb does both in one call —
 * `rollbackRevision` writes the drafts and returns the impact preview with the
 * token that binds them — so this sheet explains the act before it is taken and
 * reports the exact impact after. Nothing is published either way: the drafts
 * are ordinary, the matrix's draft dots appear, and the ordinary publish sheet
 * commits them.
 */
function RestoreSheet({
  environmentName,
  revision,
  keyName,
  result,
  busy,
  publishBusy,
  refusal,
  matrixPath,
  onStage,
  onPublish,
  onClose,
}: {
  environmentName: string;
  revision: bigint;
  keyName: string | null;
  result: RestoreSheetResult | null;
  busy: boolean;
  publishBusy: boolean;
  refusal: string | null;
  matrixPath: string;
  onStage: () => void;
  onPublish: () => void;
  onClose: () => void;
}) {
  const dialog = useModalDialog();
  const changes: readonly HistoryImpactChange[] =
    result === null
      ? []
      : result.preview.environments.flatMap((environment) =>
          environment.changes.map((change) => ({
            keyId: change.key_id,
            name: change.name,
            classification: change.classification,
            operation: change.operation,
            status: change.status,
            ...(change.before === undefined ? {} : { before: change.before }),
            ...(change.after === undefined ? {} : { after: change.after }),
          })),
        );
  const summary = restorePreviewSummary(changes);

  return (
    <dialog className="matrix-editor history-sheet" ref={dialog} onClose={onClose}>
      <div className="matrix-editor__head">
        <div>
          <h2>
            {keyName === null
              ? `Restore r${String(revision)} · ${environmentName}`
              : `Restore ${keyName} from r${String(revision)} · ${environmentName}`}
          </h2>
          <p>
            Stages drafts reproducing r{String(revision)}. Publishing them runs the normal
            pipeline and re-validates against the CURRENT schema — history is never rewritten.
          </p>
        </div>
        <button type="button" className="btn matrix-editor__close" aria-label="Close restore" onClick={onClose}>
          ✕
        </button>
      </div>

      {refusal === null ? null : (
        <p id="history-restore-refusal" className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>{refusal}</span>
        </p>
      )}

      {result === null ? (
        <div className="matrix-editor__actions">
          <button type="button" className="btn btn--primary" disabled={busy} onClick={onStage}>
            {busy ? 'Staging…' : `Stage the restore from r${String(revision)}`}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
        </div>
      ) : (
        <>
          <p className="history__chips" role="status">
            {summary.chips.map((chip) => (
              <span className="count" key={chip}>
                {chip}
              </span>
            ))}
          </p>
          <ul className="history__impact">
            {changes.map((change) => (
              <li key={change.keyId}>
                <span className="mono">
                  {change.classification === 'secret' ? <span aria-hidden="true">🔒 </span> : null}
                  {change.name}
                </span>
                <span className="history__kind">{change.operation === 'set' ? 'set' : 'clear'}</span>
                <span className="mono history__impact-values">
                  {change.classification === 'secret'
                    ? `secret — ${change.status}, write-presence only`
                    : change.operation === 'unset'
                      ? `${change.before ?? '(absent)'} → (cleared)`
                      : `${change.before ?? '(absent)'} → ${change.after ?? '(unreadable)'}`}
                </span>
              </li>
            ))}
          </ul>
          <p className="notice" role="status">
            <span aria-hidden="true">✓</span>
            <span>
              Staged as ordinary drafts. Review and publish them from the matrix — the publish
              carries the preview token that binds this exact restore.
            </span>
          </p>
          <div className="matrix-editor__actions">
            <button
              id="history-restore-publish"
              type="button"
              className="btn btn--primary"
              disabled={publishBusy || result.changes.length === 0}
              aria-describedby={result.changes.length === 0 ? 'history-restore-no-drafts' : undefined}
              onClick={onPublish}
            >
              {publishBusy
                ? 'Publishing this restore…'
                : restorePublishLabel(revision, result)}
            </button>
            <Link id="history-restore-back" className="btn" to={matrixPath}>
              Back to the matrix
            </Link>
          </div>
          {result.changes.length === 0 ? (
            <p id="history-restore-no-drafts" className="history__gate" role="status">
              Nothing changed, so this restore has no drafts to publish.
            </p>
          ) : null}
        </>
      )}
    </dialog>
  );
}

/** The pin sheet: what pinning does, to which workload, until when. */
function PinSheet({
  environmentName,
  revision,
  isCurrent,
  currentRevision,
  workloads,
  soleKeepers,
  retentionReady,
  state,
  busy,
  refusal,
  comparisonBusy,
  comparisonError,
  comparison,
  onCompare,
  onChange,
  onSubmit,
  onClose,
}: {
  environmentName: string;
  revision: bigint;
  isCurrent: boolean;
  currentRevision: bigint;
  workloads: readonly {
    readonly principalID: string;
    readonly name: string;
    readonly pinnedRevision: bigint | undefined;
    readonly pinID: string | undefined;
  }[];
  soleKeepers: ReadonlySet<string>;
  retentionReady: boolean;
  state: {
    readonly workloadPrincipalID: string;
    readonly expiresAt: string;
    readonly overrideSchema: boolean;
    readonly offerOverride: boolean;
  };
  busy: boolean;
  refusal: string | null;
  comparisonBusy: boolean;
  comparisonError: string | null;
  comparison: PinComparison | null;
  onCompare: () => void;
  onChange: (next: Partial<{ workloadPrincipalID: string; expiresAt: string; overrideSchema: boolean }>) => void;
  onSubmit: () => void;
  onClose: () => void;
}) {
  const dialog = useModalDialog();
  const chosen = workloads.find((workload) => workload.principalID === state.workloadPrincipalID);
  const plan = pinAction(chosen?.pinnedRevision, revision);
  const moveNeedsRetention = plan.kind === 'move' && !retentionReady;

  return (
    <dialog className="matrix-editor history-sheet" ref={dialog} onClose={onClose}>
      <div className="matrix-editor__head">
        <div>
          <h2>{`⚲ Pin r${String(revision)} · ${environmentName}`}</h2>
          <p>One pin per workload and environment. Quota 100 per project; expiry is mandatory.</p>
        </div>
        <button type="button" className="btn matrix-editor__close" aria-label="Close pin sheet" onClick={onClose}>
          ✕
        </button>
      </div>

      {refusal === null ? null : (
        <p id="history-pin-refusal" className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>{refusal}</span>
        </p>
      )}

      <div className="history__pin-what">
        <h3>What pinning does</h3>
        <ul>
          <li>
            The workload keeps receiving exactly r{String(revision)}&apos;s values — across
            restarts and redeploys — instead of following latest.
          </li>
          <li>
            New publishes to {environmentName} stop reaching this workload while the pin lives;
            everyone else still gets latest.
          </li>
          <li>r{String(revision)}&apos;s values are kept from retention clean-up while the pin exists.</li>
          <li>
            On release the workload resumes latest on its next fetch. On EXPIRY it keeps
            delivering the pinned revision until the payload is collected — expiry never silently
            changes delivery.
          </li>
        </ul>
      </div>

      {isCurrent ? null : (
        <p className="history__gate" role="status">
          Non-current revision: this routes HISTORICAL content to a workload, so it takes
          reveal-history and one disclosure ceremony over the revision&apos;s secret keys.
        </p>
      )}

      <label className="history__field" htmlFor="history-pin-workload">
        Workload
      </label>
      <select
        id="history-pin-workload"
        className="btn"
        value={state.workloadPrincipalID}
        onChange={(event) => onChange({ workloadPrincipalID: event.target.value })}
      >
        {workloads.length === 0 ? <option value="">No workloads in this project</option> : null}
        {workloads.map((workload) => (
          <option key={workload.principalID} value={workload.principalID}>
            {`${workload.name} — ${workload.pinnedRevision === undefined ? 'follows latest' : `pinned to r${String(workload.pinnedRevision)}`}`}
          </option>
        ))}
      </select>

      {plan.kind === 'move' && chosen?.pinnedRevision !== undefined ? (
        <>
          <p className="history__gate" role="status">
            {`${chosen.name} is currently pinned to r${String(chosen.pinnedRevision)} — one pin per workload, so this MOVES it to r${String(revision)} and replaces the old pin atomically.`}
          </p>
          {chosen.pinID !== undefined && soleKeepers.has(chosen.pinID) ? (
            <p id="history-pin-move-collection-warning" className="history__gate" role="alert">
              {soleKeeperReleaseConsequences(chosen.pinnedRevision)}
            </p>
          ) : null}
        </>
      ) : null}
      {moveNeedsRetention ? (
        <p className="history__gate" role="status" id="history-pin-retention-wait">
          Move disabled until the retention policy has loaded, so the old revision&apos;s collection consequence can be checked.
        </p>
      ) : null}
      {plan.kind === 'renew' ? (
        <p className="history__gate" role="status">
          {`${chosen?.name ?? 'This workload'} is already pinned to r${String(revision)}. Pinning again RENEWS it: the expiry is extended and the pin is re-validated against the current schema, which surfaces any new drift.`}
        </p>
      ) : null}

      <label className="history__field" htmlFor="history-pin-expiry">
        Expires on (default 180 days, maximum 365)
      </label>
      <input
        id="history-pin-expiry"
        className="mono"
        type="date"
        value={state.expiresAt}
        onChange={(event) => onChange({ expiresAt: event.target.value })}
      />

      {state.offerOverride ? (
        <label className="history__field history__override chk">
          <input
            type="checkbox"
            checked={state.overrideSchema}
            onChange={(event) => onChange({ overrideSchema: event.target.checked })}
          />
          <span>
            Pin despite the current-schema failure above. Pinned delivery is verbatim, so this is
            recorded as an explicit override and the pin is surfaced as drift afterwards.
          </span>
        </label>
      ) : null}

      <section className="history__comparison" aria-labelledby="history-pin-compare-heading">
        <h3 id="history-pin-compare-heading">
          {`Compare r${String(revision)} to latest (reads r${String(revision)}'s config values)`}
        </h3>
        <p>Secret lines are write-presence from the lineage, never a value comparison.</p>
        <button
          id="history-pin-compare"
          type="button"
          className="btn"
          disabled={comparisonBusy}
          aria-expanded={comparison !== null}
          aria-controls="history-pin-compare-results"
          onClick={onCompare}
        >
          {comparisonBusy ? 'Comparing…' : 'Run comparison'}
        </button>
        {comparisonError === null ? null : (
          <p id="history-pin-compare-error" className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">!</span>
            <span>{comparisonError}</span>
          </p>
        )}
        {comparison === null ? null : (
          <div id="history-pin-compare-results" role="status" aria-live="polite">
            {comparison.lines.length === 0 ? (
              <p>No set keys differ from latest.</p>
            ) : (
              <ul className="history__comparison-lines">
                {comparison.lines.map((line) => <li key={line}>{line}</li>)}
              </ul>
            )}
            {comparison.unchangedConfigKeys === 0 ? null : (
              <p>{`${String(comparison.unchangedConfigKeys)} config key${comparison.unchangedConfigKeys === 1 ? '' : 's'} unchanged`}</p>
            )}
          </div>
        )}
      </section>

      <div className="matrix-editor__actions">
        <button
          id="history-pin-submit"
          type="button"
          className="btn btn--primary"
          disabled={busy || state.workloadPrincipalID === '' || moveNeedsRetention}
          aria-describedby={moveNeedsRetention ? 'history-pin-retention-wait' : undefined}
          onClick={onSubmit}
        >
          {busy ? 'Pinning…' : plan.label}
        </button>
        <button type="button" className="btn" onClick={onClose}>
          Cancel
        </button>
      </div>
      <p>{`Latest in ${environmentName} is r${String(currentRevision)}.`}</p>
    </dialog>
  );
}

/** The sole-keeper release confirmation: three consequences and a danger label. */
function ReleaseSheet({
  pin,
  currentRevision,
  workloadName,
  busy,
  releaseAllowed,
  onRelease,
  onClose,
}: {
  pin: HistoryPin;
  currentRevision: bigint;
  workloadName: string;
  busy: boolean;
  releaseAllowed: boolean;
  onRelease: () => void;
  onClose: () => void;
}) {
  const dialog = useModalDialog();
  return (
    <dialog className="matrix-editor history-sheet" ref={dialog} onClose={onClose}>
      <div className="matrix-editor__head">
        <div>
          <h2>{SOLE_KEEPER_RELEASE_TITLE}</h2>
          <p id="history-release-consequence" role="alert">{soleKeeperReleaseConsequences(pin.revision)}</p>
        </div>
        <button type="button" className="btn matrix-editor__close" aria-label="Close release confirmation" onClick={onClose}>
          ✕
        </button>
      </div>
      <ul className="history__consequences">
        <li>{`r${String(pin.revision)} is past normal retention — this pin is the only thing keeping its values.`}</li>
        <li>If a retention sweep collects the values, restore, reveal, and export stop; the lineage entry stays.</li>
        <li>{`${workloadName} resumes latest (r${String(currentRevision)}) on its next fetch.`}</li>
      </ul>
      {releaseAllowed ? null : (
        <p className="alert" role="alert" id="history-release-sheet-disabled">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>Release disabled because the retention policy is no longer available.</span>
        </p>
      )}
      <div className="matrix-editor__actions">
        <button
          id="history-release-confirm"
          type="button"
          className="btn btn--danger"
          disabled={busy || !releaseAllowed}
          aria-describedby={releaseAllowed ? undefined : 'history-release-sheet-disabled'}
          onClick={onRelease}
        >
          {busy ? 'Releasing…' : SOLE_KEEPER_RELEASE_BUTTON}
        </button>
        <button type="button" className="btn" onClick={onClose}>
          Keep the pin
        </button>
      </div>
    </dialog>
  );
}

function toHistoryRevision(item: HistoryRevisionItem): HistoryRevision {
  const shared = {
    revision: item.revision,
    schemaRevision: item.schema_revision,
    publishedBy: item.published_by,
    publishedAt: item.published_at,
    changedKeys: item.changed_keys.map((changed) => ({
      keyId: changed.key_id,
      name: changed.name,
      change: changed.change,
    })),
  };
  if (item.payload_present) {
    return { ...shared, payloadPresent: true };
  }
  if (item.collected_policy === undefined) {
    throw new Error(`Collected revision r${String(item.revision)} does not name its retention policy.`);
  }
  return { ...shared, payloadPresent: false, collectedPolicy: item.collected_policy };
}

function historyMutationRefusal(
  error: unknown,
  action: 'restore' | 'pin',
  unit: readonly CeremonyKey[],
  environmentName: string,
): string {
  if (error instanceof ApiError && error.status === 403 && unit.length > 0) {
    return (
      `Refused: reading the earlier secret values of ${unit.map((key) => key.name).join(', ')} ` +
      `requires reveal-history on ${environmentName}.`
    );
  }
  return historyRefusalText(error, action);
}

function revisionDetailRefusal(error: unknown, revision: bigint): string {
  const detailed = callerSafeRefusal(error, `Revision r${String(revision)} detail refused`);
  if (detailed !== null) {
    return detailed;
  }
  if (error instanceof ApiError) {
    return `Revision r${String(revision)} detail could not be read (error ${String(error.status)}).`;
  }
  return `Revision r${String(revision)} detail could not be read.`;
}

function comparisonRefusal(error: unknown, revision: bigint): string {
  const detailed = callerSafeRefusal(error, `Comparison of r${String(revision)} refused`);
  if (detailed !== null) {
    return detailed;
  }
  if (error instanceof ApiError) {
    return `Comparison of r${String(revision)} could not be read (error ${String(error.status)}).`;
  }
  return `Comparison of r${String(revision)} could not be read.`;
}

function restorePublishLabel(revision: bigint, result: RestoreSheetResult): string {
  const preview = result.preview.environments[0];
  if (preview === undefined) {
    throw new Error('restore result has no preview environment');
  }
  return `Publish this restore (r${String(revision)} → r${String(preview.base_revision + 1n)})`;
}

function toHistoryPin(pin: RevisionPinItem): HistoryPin {
  return {
    id: pin.id,
    workloadPrincipalId: pin.workload_principal_id,
    revision: pin.revision,
    expiresAt: pin.expires_at,
    expired: pin.expired,
    schemaOverride: pin.schema_override,
  };
}

/** A prefixed UUIDv7 is unreadable at a glance; the whole one lives in `title`. */
function shortPrincipal(id: string): string {
  const separator = id.indexOf('_');
  return separator < 0 ? id : `${id.slice(0, separator + 1)}${id.slice(separator + 1, separator + 9)}…`;
}
