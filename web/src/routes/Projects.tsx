import { generatePath, Link } from 'react-router';

import { useProjects } from '../api/matrix.ts';
import { useOrgs } from '../api/session.ts';
import { surfaceById } from '../app/navigation.ts';

/** Projects is a real data surface; keeping it out of Placeholder preserves the chrome skeleton seam. */
export function Projects() {
  const orgs = useOrgs(true);
  const org = orgs.data?.items[0];
  const projects = useProjects(org?.id ?? '');

  return (
    <section className="card projects" aria-labelledby="projects-title">
      <h1 id="projects-title">Projects</h1>
      {orgs.isPending || (org !== undefined && projects.isPending) ? (
        <p role="status">Loading projects…</p>
      ) : null}
      {orgs.isError || projects.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>Projects could not be loaded. Reload to try again.</span>
        </p>
      ) : null}
      {orgs.isSuccess && org === undefined ? (
        <p role="status">No organisation is available for project navigation.</p>
      ) : null}
      {projects.isSuccess && projects.data.items.length === 0 ? (
        <p role="status">No projects yet.</p>
      ) : null}
      {org === undefined ? null : (
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
                  org: org.id,
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
