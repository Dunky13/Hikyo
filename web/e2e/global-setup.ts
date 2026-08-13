import { startInstance, stopInstance } from './fixtures/instance.ts';
import { liveClosureViolations, resetRunLog } from './registry.ts';

/**
 * Global setup runs the registry's closure check FIRST, before a browser
 * starts. A suite that is missing a flow should say so in two seconds, not
 * after it has finished passing every flow it does have.
 */
export default async function globalSetup(): Promise<void> {
  const problems = liveClosureViolations();
  if (problems.length > 0) {
    throw new Error(`the flow registry is not closed:\n  - ${problems.join('\n  - ')}`);
  }
  // A previous run's log must not vouch for this one.
  resetRunLog();
  try {
    await startInstance();
  } catch (err) {
    // A setup failure means Playwright never runs globalTeardown; without this
    // the just-spawned servers outlive the runner and poison the next run's
    // port preflight.
    stopInstance();
    throw err;
  }
}
