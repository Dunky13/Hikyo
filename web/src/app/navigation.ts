/**
 * The closed list of surfaces this build serves.
 *
 * This is not a convenience table. It is the SOURCE OF TRUTH the flow
 * registry closes over (e2e/registry.ts): every surface named here must be
 * covered by a Playwright flow, and the closure check fails the build when
 * one is not. Adding a route without adding it here would defeat that, so the
 * router is built FROM this list — there is no second place to declare a
 * route.
 *
 * `section` is null for surfaces that are not navigation destinations (the
 * login page is reached by not being signed in, never by choosing it).
 */

export type SurfaceId =
  | 'login'
  | 'overview'
  | 'projects'
  | 'settings'
  | 'matrix'
  | 'history'
  | 'values'
  | 'machine-access'
  | 'remotes'
  | 'cli-reauth'
  | 'workspace-approve'
  | 'workspace-callback';

export type Surface = {
  readonly id: SurfaceId;
  readonly path: string;
  readonly label: string;
  readonly section: string | null;
};

export const SURFACES: readonly Surface[] = [
  { id: 'login', path: '/login', label: 'Sign in', section: null },
  { id: 'overview', path: '/', label: 'Overview', section: 'Organisation' },
  { id: 'projects', path: '/projects', label: 'Projects', section: 'Organisation' },
  { id: 'remotes', path: '/remotes', label: 'Remotes', section: 'Organisation' },
  { id: 'settings', path: '/settings', label: 'Settings', section: 'Account' },
  // The environment matrix addresses one whole project. Like the
  // environment-scoped value surface, its org and project are route data, so
  // no static sidebar destination can point at it honestly.
  {
    id: 'matrix',
    path: '/orgs/:org/projects/:project/matrix',
    label: 'Environment matrix',
    section: null,
  },
  // The revision-history drawer (#59). It is the matrix WITH its history drawer
  // open — the locked prototype's list+detail panes render over the matrix, not
  // instead of it — so the path nests under the matrix and the element is the
  // same component. `section: null` for the matrix's own reason: it addresses
  // one project, and the environment and the per-key filter are query
  // parameters, because per-key history is a filter and not a second surface.
  {
    id: 'history',
    path: '/orgs/:org/projects/:project/matrix/history',
    label: 'Revision history',
    section: null,
  },
  // The reveal / copy / write-only-edit surface (#58). `section: null` because
  // it is not a navigation destination: it addresses one environment of one
  // project, so it is reached from the matrix and by deep link, never from a
  // static sidebar entry that could not know which environment to mean.
  {
    id: 'values',
    path: '/orgs/:org/projects/:project/environments/:environment/values',
    label: 'Values',
    section: null,
  },
  // The machine-access surface (#67). `section: null` for the same reason
  // `values` is: it addresses ONE project, and a static sidebar entry could not
  // know which. It is reached from the project and by deep link. The
  // project-scoped navigation the prototype draws around it is the shell's own
  // ticket, not this one.
  {
    id: 'machine-access',
    path: '/orgs/:org/projects/:project/machine-access',
    label: 'Machine access',
    section: null,
  },
  // Browser half of the CLI's purpose-bound reauthentication handoff. The
  // opaque transaction state stays in the query string so login can render on
  // this same route without losing it.
  { id: 'cli-reauth', path: '/reauth/cli', label: 'Authorize CLI', section: null },
  // The two ceremony pages. Neither is a navigation destination and neither
  // wears the chrome: they are the two ends of the workspace handoff's front
  // channel, and both are reached by a redirect, never by choosing them.
  //
  // `workspace-approve` is served by the SERVING instance and is where the
  // popup lands — the human authenticates there with that instance's own
  // ceremonies, on that instance's own origin, which is the whole architecture
  // in one route. `workspace-callback` is served by the VIEWING instance and
  // is the same-origin return path that exists because the popup is opened
  // with `noopener` and therefore has no `window.opener` to talk back through.
  { id: 'workspace-approve', path: '/workspace/approve', label: 'Authorize workspace', section: null },
  { id: 'workspace-callback', path: '/workspace/callback', label: 'Returning', section: null },
];

export type Section = {
  readonly title: string;
  readonly items: readonly Surface[];
};

/** SECTIONS is the sidebar, derived so it cannot drift from the surface list. */
export const SECTIONS: readonly Section[] = Object.entries(
  SURFACES.filter((s) => s.section !== null).reduce<Record<string, Surface[]>>((acc, surface) => {
    const key = surface.section ?? '';
    (acc[key] ??= []).push(surface);
    return acc;
  }, {}),
).map(([title, items]) => ({ title, items }));

/**
 * CHROMELESS is every surface that renders WITHOUT the application chrome AND
 * without a session — the login page and the two workspace ceremony pages.
 *
 * DECLARED, not derived from `section === null`, and the counterexample is
 * `values`: it is not a navigation destination either (it addresses one
 * environment of one project, so it is reached from the matrix, never from a
 * static sidebar entry), yet it is a signed-in surface that wears the chrome
 * like any other. Deriving this set from `section` would have made the reveal
 * surface publicly routable the moment both tickets met — the two properties
 * look alike and are not the same property.
 *
 * A popup 520px wide showing an org rail would be chrome around a consent
 * decision, which is why the ceremony pages are here; and the approve page in
 * particular must render for a caller with NO session at all, or a first
 * establishment would be bounced to `/login` and lose the `state` the whole
 * transaction is addressed by.
 */
const CHROMELESS_IDS: readonly SurfaceId[] = [
  'login',
  'cli-reauth',
  'workspace-approve',
  'workspace-callback',
];

export const CHROMELESS: readonly Surface[] = SURFACES.filter((s) =>
  CHROMELESS_IDS.includes(s.id),
);

export function surfaceById(id: SurfaceId): Surface {
  const found = SURFACES.find((s) => s.id === id);
  if (found === undefined) {
    throw new Error(`unknown surface ${id}`);
  }
  return found;
}
