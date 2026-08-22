/**
 * Pure state for the revision-history drawer (#59, frozen prototype
 * `revision-history/6`).
 *
 * Kept free of React and API clients for the same reason `matrix-state.ts` is:
 * these are the drawer's domain decisions — what a pin mutation actually does,
 * which revisions a collected payload takes off the table, and what the impact
 * preview summarises to. Retention consequences are server vocabulary: the
 * list carries a confirmation preview and the release response carries the
 * authoritative transaction-time decision.
 *
 * Revision numbers are `bigint` throughout, because that is what the generated
 * Zod hands the boundary (`int64`). Mixing them with `number` is how an
 * ordering comparison silently stops being one.
 */

import type { RetentionConsequence } from '@hikyo/client';

export type HistoryChangedKey = {
  readonly keyId: string;
  readonly name: string;
  readonly change: 'added' | 'edited' | 'removed';
};

type HistoryRevisionBase = {
  readonly revision: bigint;
  readonly schemaRevision: bigint;
  readonly publishedBy: string;
  readonly publishedAt: string;
  readonly changedKeys: readonly HistoryChangedKey[];
};

export type HistoryRevision = HistoryRevisionBase &
  (
    | {
        /** A live payload carries no collection policy. */
        readonly payloadPresent: true;
        readonly collectedPolicy?: never;
      }
    | {
        /** The lineage survives collection and permanently names its policy. */
        readonly payloadPresent: false;
        readonly collectedPolicy: string;
      }
  );

export type RevisionActionGate = {
  readonly restore: boolean;
  readonly pin: boolean;
  /** Why the refused actions are refused, in the words the surface renders. */
  readonly reason: string | null;
};

/**
 * revisionActionGate decides which of the drawer's two mutations a revision
 * still admits, and says why when it does not.
 *
 * A collected payload closes both, naming the policy the store stamped at
 * collection — that string is what the server's own refusal reports forever, so
 * the UI repeats it rather than paraphrasing. The current revision closes only
 * restore: restoring it compares a state against itself and stages nothing,
 * which the service answers with an empty change set rather than an error, and
 * an enabled button whose whole outcome is "nothing happened" is a lie.
 */
export function revisionActionGate(
  revision: HistoryRevision,
  currentRevision: bigint,
): RevisionActionGate {
  if (!revision.payloadPresent) {
    return {
      restore: false,
      pin: false,
      reason:
        `r${String(revision.revision)}'s payload was collected by retention policy ${revision.collectedPolicy} — ` +
        'restore and pin are refused; the lineage stays.',
    };
  }
  if (revision.revision === currentRevision) {
    return {
      restore: false,
      pin: true,
      reason: `r${String(revision.revision)} is already the current revision — a restore would stage nothing.`,
    };
  }
  return { restore: true, pin: true, reason: null };
}

/**
 * revisionsForKeyFilter is the per-key history projection.
 *
 * Per-key history is a FILTER over the same lineage, never a second surface —
 * the locked prototype's first decision — so it is a projection here and a
 * query parameter in the route, not a different fetch.
 *
 * The query carries the immutable key ID. Names can change and can be reused
 * after deletion; neither event changes which lineage belongs to this key.
 */
export function revisionsForKeyFilter(
  revisions: readonly HistoryRevision[],
  keyId: string | null,
): readonly HistoryRevision[] {
  if (keyId === null || keyId === '') {
    return revisions;
  }
  return revisions.filter((revision) =>
    revision.changedKeys.some((changed) => changed.keyId === keyId),
  );
}

export type HistoryCatalogueKey = { readonly id: string; readonly name: string };
export type HistoryKeyDisplay = {
  readonly name: string;
  readonly label: string;
  readonly current: boolean;
};

/** Resolves a key-id filter without hiding whether the displayed name is current or historical. */
export function historyKeyDisplay(
  keyId: string,
  catalogue: readonly HistoryCatalogueKey[],
  revision: HistoryRevision | undefined,
): HistoryKeyDisplay {
  const current = catalogue.find((key) => key.id === keyId);
  if (current !== undefined) {
    return { name: current.name, label: `${current.name} (current name)`, current: true };
  }
  const historical = revision?.changedKeys.find((key) => key.keyId === keyId);
  if (historical === undefined) {
    throw new Error(`History filter names unknown key ${keyId}.`);
  }
  return {
    name: historical.name,
    label: `${historical.name} (historical name; key no longer exists)`,
    current: false,
  };
}

/** The rollback wire addresses a key by its current catalogue name, never its historical name. */
export function restoreKeyName(
  keyId: string,
  catalogue: readonly HistoryCatalogueKey[],
  revision: HistoryRevision,
): string {
  const current = catalogue.find((key) => key.id === keyId);
  if (current !== undefined) {
    return current.name;
  }
  const historical = historyKeyDisplay(keyId, catalogue, revision);
  throw new Error(
    `Cannot restore ${historical.name}: key ${keyId} no longer exists in the current catalogue.`,
  );
}

export type PinActionKind = 'pin' | 'move' | 'renew';

export type PinActionPlan = {
  readonly kind: PinActionKind;
  /** What the sheet's primary button says. */
  readonly label: string;
};

/**
 * pinAction names what pinning THIS revision does to THIS workload.
 *
 * A pin is a workload binding — at most one per (workload, environment) — so
 * the same gesture is three different acts depending on where that workload
 * already points, and the sheet has to say which one before it is taken.
 *
 * **Divergence from the locked prototype, deliberately.** Iteration 4 refuses a
 * same-revision re-pin as a no-op ("a workload fetches exactly one revision").
 * The API/CLI taxonomy locked afterwards (#52) makes it a RENEW: it extends the
 * expiry, revalidates against the current schema, and records the drift that
 * revalidation finds. That is not nothing, so the button says "renew" rather
 * than being disabled. The server is the authority on which of the three it
 * performed; this label is what the human is asked to agree to, and the outcome
 * toast comes from `RevisionPinResult.action`.
 */
export function pinAction(
  pinnedRevision: bigint | undefined,
  targetRevision: bigint,
): PinActionPlan {
  if (pinnedRevision === undefined) {
    return { kind: 'pin', label: 'Create pin' };
  }
  if (pinnedRevision === targetRevision) {
    return {
      kind: 'renew',
      label: `Renew pin on r${String(targetRevision)}`,
    };
  }
  return {
    kind: 'move',
    label: `Move pin from r${String(pinnedRevision)} to r${String(targetRevision)}`,
  };
}

export type PinExpiryTier = 'ok' | 'month' | 'week' | 'day' | 'expired';

export type PinExpiry = {
  /** Display days: ceiled while live, zero or negative once expired. */
  readonly days: number;
  readonly tier: PinExpiryTier;
  /** The row's own words. Never colour-only: the tier is legible as text. */
  readonly text: string;
};

const DAY_MS = 24 * 60 * 60 * 1_000;

/**
 * pinExpiry is the 30 / 7 / 1-day warning ladder #52 deferred to this surface.
 *
 * Two properties are load-bearing:
 *
 *  - **The tier is spelled, not coloured.** `!`, `!!`, `!!!` ride in the text,
 *    so the escalation survives forced-colours and a screen reader.
 *  - **An expired pin is not a dead pin.** Expiry never changes delivery: the
 *    workload keeps receiving the pinned revision until its payload is
 *    collected (#52), and a row that said "expired" and stopped there would
 *    have someone chasing an outage that is not happening. The row says so.
 */
export function pinExpiry(expiresAt: string, now: Date): PinExpiry {
  const remaining = new Date(expiresAt).getTime() - now.getTime();
  if (remaining <= 0) {
    return {
      days: Math.floor(remaining / DAY_MS),
      tier: 'expired',
      text: 'expired — still delivering until its payload is collected',
    };
  }
  const days = Math.ceil(remaining / DAY_MS);
  if (remaining < DAY_MS) {
    return { days, tier: 'day', text: '!!! expires today' };
  }
  if (remaining <= DAY_MS) {
    return { days, tier: 'day', text: '!!! expires in 1 d' };
  }
  if (remaining <= 7 * DAY_MS) {
    return { days, tier: 'week', text: `!! expires in ${String(days)} d` };
  }
  if (remaining <= 30 * DAY_MS) {
    return { days, tier: 'month', text: `! expires in ${String(days)} d` };
  }
  return { days, tier: 'ok', text: `expires in ${String(days)} d` };
}

export type HistoryRetention = {
  readonly mode: 'keep-if-either' | 'unlimited';
  readonly maxAgeSeconds: number | null;
  readonly lastRevisions: number | null;
};

export function toHistoryRetention(policy: {
  readonly mode: 'keep-if-either' | 'unlimited';
  readonly max_age_seconds?: number;
  readonly last_revisions?: number;
}): HistoryRetention {
  return {
    mode: policy.mode,
    maxAgeSeconds: policy.max_age_seconds ?? null,
    lastRevisions: policy.last_revisions ?? null,
  };
}

export type HistoryPin = {
  readonly id: string;
  readonly workloadPrincipalId: string;
  readonly revision: bigint;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly schemaOverride: boolean;
  readonly releaseRetentionConsequence: RetentionConsequence;
};


export type HistoryImpactChange = {
  readonly keyId: string;
  readonly name: string;
  readonly classification: 'config' | 'secret';
  readonly operation: 'set' | 'unset';
  readonly status: 'added' | 'edited' | 'removed' | 'not-edited';
  readonly before?: string;
  readonly after?: string;
};

export type RestoreSummary = {
  readonly set: number;
  readonly clear: number;
  readonly total: number;
  /** The prototype's summary chip line, prose only on the rows themselves. */
  readonly chips: readonly string[];
};

/**
 * restorePreviewSummary is the chip line above the impact rows.
 *
 * **Divergence from the locked prototype, named.** Iteration 2 gives the line a
 * third chip, "n schema-blocked", because the prototype validated the restore
 * at staging. The shipped model validates at PUBLISH — restore stages ordinary
 * drafts and publish is the only authority (#52) — so a successful preview has
 * no blocked rows to count. The schema refusal is still loud and still names
 * the keys; it arrives on the publish leg, where the server decides it.
 */
export function restorePreviewSummary(
  changes: readonly HistoryImpactChange[],
): RestoreSummary {
  const set = changes.filter((change) => change.operation === 'set').length;
  const clear = changes.filter((change) => change.operation === 'unset').length;
  const chips: string[] = [];
  if (set > 0) {
    chips.push(`${String(set)} set`);
  }
  if (clear > 0) {
    chips.push(`${String(clear)} clear`);
  }
  if (chips.length === 0) {
    chips.push('already matches — nothing to stage');
  }
  return { set, clear, total: changes.length, chips };
}

export type HistorySnapshotKey = {
  readonly keyId: string;
  readonly name: string;
  readonly classification: 'config' | 'secret';
};

export type HistoryCurrentCell = {
  readonly keyId: string;
  readonly classification: 'config' | 'secret';
  readonly set: boolean;
};

export type CeremonyKey = { readonly id: string; readonly name: string };

/**
 * restoreCeremonyUnit enumerates the secret keys a restore will decrypt.
 *
 * The server binds a purpose-bound ceremony to `(environment, sorted key ids)`
 * over exactly this set, so the modal has to list exactly it or a
 * single-decision window is spent against a binding that does not match. Both
 * sides count and they are independent (#52): the HISTORICAL secret is read to
 * stage it, and the CURRENT secret is read only to compare two set values — a
 * restore-to-absent opens no current plaintext and must not demand it.
 *
 * ponytail: written-time STICKY bits are invisible to the browser; everything
 * knowable client-side is unioned. Carry the sticky bit on `SnapshotKey` when
 * the wire exposes it so the browser can exactly reproduce the server unit.
 */
export function restoreCeremonyUnit(input: {
  readonly revisionKeys: readonly HistorySnapshotKey[];
  readonly currentCells: readonly HistoryCurrentCell[];
  readonly keyId: string | null;
}): readonly CeremonyKey[] {
  const currentByKey = new Map(input.currentCells.map((cell) => [cell.keyId, cell]));
  return input.revisionKeys
    .filter((key) => input.keyId === null || key.keyId === input.keyId)
    .filter((key) => {
      if (key.classification === 'secret') {
        return true;
      }
      const current = currentByKey.get(key.keyId);
      return current !== undefined && current.set && current.classification === 'secret';
    })
    .map((key) => ({ id: key.keyId, name: key.name }));
}

/**
 * pinCeremonyUnit unions the pinned revision's and current catalogue's known
 * secret classifications.
 *
 * Pinning a non-current revision is disclosure BY PROXY: it routes historical
 * secret material to a workload, so the server takes `reveal-history` and one
 * ceremony over the snapshot's secrets, and audits each of them against the
 * pinned revision.
 */
export function pinCeremonyUnit(
  revisionKeys: readonly HistorySnapshotKey[],
  currentCells: readonly HistoryCurrentCell[],
): readonly CeremonyKey[] {
  const currentByKey = new Map(currentCells.map((cell) => [cell.keyId, cell]));
  return revisionKeys
    .filter(
      (key) =>
        key.classification === 'secret' ||
        currentByKey.get(key.keyId)?.classification === 'secret',
    )
    .map((key) => ({ id: key.keyId, name: key.name }));
}

export type RetentionLine = {
  readonly window: string;
  readonly badge: 'inherits org' | 'custom';
  readonly badgeTitle: string;
};

/**
 * retentionLine is the drawer head's READ-ONLY retention statement.
 *
 * The locked prototype moved editing to the settings surfaces at iteration 6:
 * the retention knob is `project-settings` / org-policy authority, and this
 * surface reports the policy rather than owning it. So there is no stepper here
 * and no write path — only the effective window, whether it is inherited, and a
 * pointer at where it is changed (#60's surface).
 */
export function retentionLine(policy: HistoryRetention & {
  readonly inherited: boolean;
}): RetentionLine {
  const badge = policy.inherited ? 'inherits org' : 'custom';
  const badgeTitle = policy.inherited
    ? 'this project has no retention of its own — it follows the org default and moves when the org value moves'
    : 'this project overrode the org default — org changes no longer touch it';
  if (policy.mode === 'unlimited' || policy.maxAgeSeconds === null || policy.lastRevisions === null) {
    return {
      window: 'values kept: unlimited — no payload is ever collected',
      badge,
      badgeTitle,
    };
  }
  const days = Math.round(policy.maxAgeSeconds / (24 * 60 * 60));
  return {
    window:
      `values kept: ${String(days)} d or the last ${String(policy.lastRevisions)} revisions, ` +
      'whichever is longer, plus pinned',
    badge,
    badgeTitle,
  };
}

/**
 * pinSchemaOverrideOffered decides whether to put the override in front of the
 * human at all.
 *
 * The checkbox is offered ONLY after the server has actually refused for a
 * current-schema failure — never up front. An override that is always on screen
 * is an override people tick to make an error go away; one that appears with
 * the refusal it answers is a decision, and #52 records it as such (and only
 * when it is actually consumed).
 */
export function pinSchemaOverrideOffered(detail: string | undefined): boolean {
  if (detail === undefined || detail === '') {
    return false;
  }
  // ponytail: replace this prose match with a structured schema-refusal code in
  // the Error contract once the API exposes one. Until then this is a POSITIVE
  // match on the three refusals `validateResolved` (internal/service/publish.go)
  // can raise — a value rule, a presence rule, a key-group rule — which is the
  // whole set `override_schema` exists to override. Anything else is refused for
  // a reason an override cannot fix, and the checkbox stays away.
  return (
    /^value for "[^"]+" is invalid \(/.test(detail) ||
    (detail.startsWith('key "') && detail.endsWith(': publish is vetoed')) ||
    (detail.startsWith('key group ') && detail.endsWith("a group's presence is all-or-none"))
  );
}

/** The service's own default pin lifetime (180 days), as a `<input type=date>` value. */
export function defaultPinExpiry(now: Date): string {
  const at = new Date(now.getTime());
  at.setDate(at.getDate() + 180);
  return localDateInputValue(at);
}

function localDateInputValue(date: Date): string {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${String(date.getFullYear())}-${month}-${day}`;
}

/**
 * Converts an `<input type=date>` local calendar day to its end-of-local-day
 * instant. "Expires on" therefore includes the entire date the human chose.
 */
export function pinExpiryInstant(dateInputValue: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateInputValue);
  if (match === null) {
    throw new Error(`Invalid pin expiry date: ${dateInputValue}`);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const instant = new Date(year, month - 1, day, 23, 59, 59, 999);
  if (
    instant.getFullYear() !== year ||
    instant.getMonth() !== month - 1 ||
    instant.getDate() !== day
  ) {
    throw new Error(`Invalid pin expiry date: ${dateInputValue}`);
  }
  return instant.toISOString();
}

/** Human-readable workload identity with the complete id retained by the caller's title. */
export function workloadLabel(id: string, names: ReadonlyMap<string, string>): string {
  const name = names.get(id);
  if (name !== undefined) {
    return name;
  }
  const separator = id.indexOf('_');
  return separator < 0 ? id : `${id.slice(0, separator + 1)}${id.slice(separator + 1, separator + 9)}…`;
}

export type PinHistoricalValue = {
  readonly name: string;
  readonly classification: 'config' | 'secret';
  readonly revealed: boolean;
  readonly value?: string;
};

export type PinLatestValue = {
  readonly keyId: string;
  readonly name: string;
  readonly classification: 'config' | 'secret';
  readonly set: boolean;
  readonly revealed: boolean;
  readonly value?: string;
};

export type PinComparison = {
  readonly lines: readonly string[];
  readonly unchangedConfigKeys: number;
};

/** Builds the pin comparison without ever comparing secret material. */
export function pinComparedToLatest(input: {
  readonly revision: bigint;
  readonly revisionKeys: readonly HistorySnapshotKey[];
  readonly historical: readonly PinHistoricalValue[];
  readonly latest: readonly PinLatestValue[];
  readonly laterRevisions: readonly HistoryRevision[];
}): PinComparison {
  const historicalByName = new Map(input.historical.map((value) => [value.name, value]));
  const latestByKey = new Map(input.latest.map((value) => [value.keyId, value]));
  const revisionKeyIDs = new Set(input.revisionKeys.map((key) => key.keyId));
  const lines: string[] = [];
  let unchangedConfigKeys = 0;

  for (const historical of input.historical) {
    if (!input.revisionKeys.some((key) => key.name === historical.name)) {
      throw new Error(`Historical export returned unknown key ${historical.name}.`);
    }
    assertComparisonValue(historical, 'historical');
  }
  for (const latest of input.latest) {
    if (latest.set) {
      assertComparisonValue(latest, 'latest');
    }
  }

  const keys = [
    ...input.revisionKeys,
    ...input.latest
      .filter((latest) => !revisionKeyIDs.has(latest.keyId))
      .map((latest) => ({
        keyId: latest.keyId,
        name: latest.name,
        classification: latest.classification,
      })),
  ];

  for (const key of keys) {
    const historical = historicalByName.get(key.name);
    const latest = latestByKey.get(key.keyId);
    const hadHistorical = historical !== undefined;
    const hasLatest = latest?.set === true;
    if (!hadHistorical && !hasLatest) {
      continue;
    }
    if (!hadHistorical) {
      lines.push(`won't have ${latest?.name ?? key.name}`);
      continue;
    }
    if (!hasLatest) {
      lines.push(`keeps ${key.name}`);
      continue;
    }

    const secret =
      historical.classification === 'secret' ||
      latest.classification === 'secret' ||
      key.classification === 'secret';
    if (secret) {
      const latestWrite = input.laterRevisions.reduce<HistoryRevision | undefined>(
        (latestRevision, revision) =>
          revision.changedKeys.some((entry) => entry.keyId === key.keyId) &&
          (latestRevision === undefined || revision.revision > latestRevision.revision)
            ? revision
            : latestRevision,
        undefined,
      );
      lines.push(
        latestWrite === undefined
          ? `${key.name} not written since r${String(input.revision)}`
          : `${key.name} written again since r${String(input.revision)} (r${String(latestWrite.revision)})`,
      );
      continue;
    }

    if (historical.value === latest.value) {
      unchangedConfigKeys += 1;
    } else {
      lines.push(`${key.name} stays at ${historical.value} — latest: ${latest.value}`);
    }
  }

  return { lines, unchangedConfigKeys };
}

function assertComparisonValue(
  value: {
    readonly name: string;
    readonly classification: 'config' | 'secret';
    readonly revealed: boolean;
    readonly value?: string;
  },
  source: 'historical' | 'latest',
): void {
  if (value.classification === 'secret') {
    if (value.revealed || value.value !== undefined) {
      throw new Error(`${source} secret ${value.name} exposed material in a pin comparison.`);
    }
    return;
  }
  if (!value.revealed || value.value === undefined) {
    throw new Error(`${source} config ${value.name} has no readable value for comparison.`);
  }
}

const RELATIVE = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

/**
 * relativeAge is the timeline's "when", in the platform's own words.
 *
 * `Intl.RelativeTimeFormat` rather than a hand-rolled ladder: it is already in
 * every browser this SPA supports, it pluralises and it localises, and the three
 * lines here only pick which unit to hand it.
 */
export function relativeAge(publishedAt: string, now: Date): string {
  const seconds = (new Date(publishedAt).getTime() - now.getTime()) / 1_000;
  if (Math.abs(seconds) < 60) {
    return RELATIVE.format(0, 'second');
  }
  if (Math.abs(seconds) < 3_600) {
    return RELATIVE.format(Math.round(seconds / 60), 'minute');
  }
  if (Math.abs(seconds) < 86_400) {
    return RELATIVE.format(Math.round(seconds / 3_600), 'hour');
  }
  return RELATIVE.format(Math.round(seconds / 86_400), 'day');
}
