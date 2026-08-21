import type { ReactElement } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';

import { useSession } from '../api/session.ts';
import { AccountSecurity } from '../routes/AccountSecurity.tsx';
import { CLIReauth } from '../routes/CLIReauth.tsx';
import { InstanceAdmin } from '../routes/InstanceAdmin.tsx';
import { Login } from '../routes/Login.tsx';
import { MachineAccess } from '../routes/MachineAccess.tsx';
import { Matrix } from '../routes/Matrix.tsx';
import { Members } from '../routes/Members.tsx';
import { OrgSettings } from '../routes/OrgSettings.tsx';
import { NotFound, Overview } from '../routes/Placeholder.tsx';
import { ProjectSettings } from '../routes/ProjectSettings.tsx';
import { Projects } from '../routes/Projects.tsx';
import { Remotes } from '../routes/Remotes.tsx';
import { Shell } from '../routes/Shell.tsx';
import { Values } from '../routes/Values.tsx';
import { WorkspaceApprove } from '../routes/WorkspaceApprove.tsx';
import { WorkspaceCallback } from '../routes/WorkspaceCallback.tsx';
import { WorkspaceScope } from '../routes/WorkspaceScope.tsx';
import { CHROMELESS, SURFACES, surfaceById, type Surface, type SurfaceId } from './navigation.ts';

/**
 * ELEMENTS is what each locked surface renders.
 *
 * `Record<SurfaceId, …>` is the structural half of the flow registry's
 * closure: a surface added to `navigation.ts` does not compile until it has an
 * element here, and an element cannot exist for a surface the table does not
 * name. The routes below are then GENERATED from the table, so there is no
 * hand-written `<Route path=…>` for a new page to hide in — which is what the
 * S3 gate needs to stay true rather than merely be true today.
 */
const ELEMENTS: Record<SurfaceId, ReactElement> = {
  login: <Login />,
  overview: <Overview />,
  projects: <Projects />,
  remotes: <Remotes />,
  members: <Members />,
  'org-settings': <OrgSettings />,
  'project-settings': <ProjectSettings />,
  'instance-admin': <InstanceAdmin />,
  settings: <AccountSecurity />,
  // The three product surfaces are wrapped in WorkspaceScope: reached with a
  // `?remote=<name>` parameter they operate that remote over its bearer, and
  // without one they render exactly as before against this instance (#71).
  matrix: (
    <WorkspaceScope>
      <Matrix />
    </WorkspaceScope>
  ),
  // The same surface with its history drawer open. The route table is the only
  // place that knows the path, so the element reads the state as a prop rather
  // than sniffing the location.
  history: (
    <WorkspaceScope>
      <Matrix historyOpen />
    </WorkspaceScope>
  ),
  values: (
    <WorkspaceScope>
      <Values />
    </WorkspaceScope>
  ),
  'machine-access': <MachineAccess />,
  'cli-reauth': <CLIReauth />,
  'workspace-approve': <WorkspaceApprove />,
  'workspace-callback': <WorkspaceCallback />,
};

/**
 * The surfaces that render inside the chrome and behind a session: everything
 * that is not chromeless. Complement of CHROMELESS rather than
 * `section !== null`, because `values` has no section and is still a chromed,
 * signed-in surface — see the note on CHROMELESS.
 */
const shellSurfaces: readonly Surface[] = SURFACES.filter((s) => !CHROMELESS.includes(s));

/**
 * The chromeless surfaces reachable WITHOUT a session.
 *
 * The approve page is here deliberately and it is the non-obvious one: a first
 * establishment lands in a popup carrying no cookies for this instance at all,
 * so bouncing it to `/login` would throw away the `state` the whole transaction
 * is addressed by. It renders the sign-in form itself instead, and the URL —
 * with its state — survives.
 *
 * The callback page is here for a duller reason: it only reads two query
 * parameters and shouts them down a channel, and making that depend on a
 * session would break the one arc where the human has no session yet.
 */
const publicSurfaces: readonly Surface[] = CHROMELESS;

/**
 * The application root.
 *
 * Two states, decided by one question asked once per load: `whoami` either
 * resolves a live session or answers 401. There is no third "maybe" state and
 * no optimistic render of the chrome — showing an org rail to someone who is
 * about to be bounced to the login page is a flash of somebody else's data.
 */
export function App() {
  const session = useSession();

  if (session.isPending) {
    // Deliberately quiet: this resolves in one round trip against a local
    // server, and a spinner that appears for 20ms is noise, not feedback.
    return (
      <p className="login" role="status">
        Loading…
      </p>
    );
  }

  if (session.isError) {
    return (
      <main className="login">
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>Could not reach the server. Reload once it is back.</span>
        </p>
      </main>
    );
  }

  const live = session.data;

  return (
    <BrowserRouter>
      {live === null ? (
        <Routes>
          {publicSurfaces.map((surface) => (
            <Route key={surface.id} path={surface.path} element={ELEMENTS[surface.id]} />
          ))}
          <Route path="*" element={<Navigate to={surfaceById('login').path} replace />} />
        </Routes>
      ) : (
        <Routes>
          <Route
            path={surfaceById('login').path}
            element={<Navigate to={surfaceById('overview').path} replace />}
          />
          {publicSurfaces
            .filter((surface) => surface.id !== 'login')
            .map((surface) => (
              <Route key={surface.id} path={surface.path} element={ELEMENTS[surface.id]} />
            ))}
          <Route element={<Shell session={live} />}>
            {shellSurfaces.map((surface) => (
              <Route key={surface.id} path={surface.path} element={ELEMENTS[surface.id]} />
            ))}
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      )}
    </BrowserRouter>
  );
}
