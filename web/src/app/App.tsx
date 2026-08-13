import type { ReactElement } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';

import { useSession } from '../api/session.ts';
import { Login } from '../routes/Login.tsx';
import { MachineAccess } from '../routes/MachineAccess.tsx';
import { NotFound, Overview, Projects, Settings } from '../routes/Placeholder.tsx';
import { Shell } from '../routes/Shell.tsx';
import { Values } from '../routes/Values.tsx';
import { SURFACES, surfaceById, type Surface, type SurfaceId } from './navigation.ts';

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
  settings: <Settings />,
  values: <Values />,
  'machine-access': <MachineAccess />,
};

const signedInSurfaces: readonly Surface[] = SURFACES.filter((s) => s.id !== 'login');

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
          <Route path={surfaceById('login').path} element={ELEMENTS.login} />
          <Route path="*" element={<Navigate to={surfaceById('login').path} replace />} />
        </Routes>
      ) : (
        <Routes>
          <Route
            path={surfaceById('login').path}
            element={<Navigate to={surfaceById('overview').path} replace />}
          />
          <Route element={<Shell session={live} />}>
            {signedInSurfaces.map((surface) => (
              <Route key={surface.id} path={surface.path} element={ELEMENTS[surface.id]} />
            ))}
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      )}
    </BrowserRouter>
  );
}
