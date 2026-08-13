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

export type SurfaceId = 'login' | 'overview' | 'projects' | 'settings' | 'values';

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
  { id: 'settings', path: '/settings', label: 'Settings', section: 'Account' },
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

export function surfaceById(id: SurfaceId): Surface {
  const found = SURFACES.find((s) => s.id === id);
  if (found === undefined) {
    throw new Error(`unknown surface ${id}`);
  }
  return found;
}
