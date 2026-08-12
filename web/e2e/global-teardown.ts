import type { FullConfig } from '@playwright/test';

import { stopInstance } from './fixtures/instance.ts';
import { readRunLog, unexecutedClaims } from './registry.ts';

/**
 * Teardown closes the half of the registry a declaration cannot: every surface
 * a flow CLAIMS must have had the pinned assertion set actually run on it.
 * Without this, adding a surface to the table, an element to the router and an
 * entry to a flow's claim list passes the closure check while asserting
 * nothing about the new page.
 *
 * It is skipped under `--grep`, and only under `--grep`: a filtered run is
 * deliberately partial, and failing it would make the check something people
 * work around instead of with. CI runs unfiltered.
 */
export default function globalTeardown(config: FullConfig): void {
  stopInstance();

  const filtered = String(config.grep) !== '/.*/';
  if (filtered) {
    process.stdout.write('flow-registry execution check skipped: this run was filtered by --grep\n');
    return;
  }
  const missing = unexecutedClaims(readRunLog());
  if (missing.length > 0) {
    throw new Error(`the flow registry claims more than it runs:\n  - ${missing.join('\n  - ')}`);
  }
}
