import { generatePath, Link, useOutletContext } from 'react-router';

import { useProjects } from '../api/matrix.ts';
import { surfaceById } from '../app/navigation.ts';

/** Projects is a real data surface; keeping it out of Placeholder preserves the chrome skeleton seam. */
export function Projects() {
  const { activeOrgId } = useOutletContext<{ readonly activeOrgId: string }>();
  const projects = useProjects(activeOrgId);

  return (
    <section className="card projects" aria-labelledby="projects-title">
      <h1 id="projects-title">Projects</h1>
      {activeOrgId !== '' && projects.isPending ? (
        <p role="status">Loading projects…</p>
      ) : null}
      {projects.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>Projects could not be loaded. Reload to try again.</span>
        </p>
      ) : null}
      {activeOrgId === '' ? (
        <p role="status">No organisation is available for project navigation.</p>
      ) : null}
      {projects.isSuccess && projects.data.items.length === 0 ? (
        <p role="status">No projects yet.</p>
      ) : null}
      {activeOrgId === '' ? null : (
        <ul className="projects__list">
          {(projects.data?.items ?? []).map((project) => (
            <li key={project.id}>
              <div>
                <strong>{project.name}</strong>
                <span className="mono">{project.id}</span>
              </div>
              <Link
                className="btn"
                to={generatePath(surfaceById('matrix').path, {
                  org: activeOrgId,
                  project: project.id,
                })}
              >
                Open matrix
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
