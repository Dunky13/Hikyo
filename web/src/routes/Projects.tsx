import { useId, useState, type FormEvent } from 'react';
import { generatePath, Link, useOutletContext } from 'react-router';

import { useProjects } from '../api/matrix.ts';
import { createProjectRefusalText, useCreateProject } from '../api/settings.ts';
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
        <p role="status" className="hint-wrap">
          None of your grants names an organisation yet. An instance administrator creates one
          under Instance administration and grants access there (Instance grants, with your
          principal ID from Account &amp; security), or from a terminal with{' '}
          <code>hikyo access grant template</code>. A grant on your own account ends the current
          session.
        </p>
      ) : (
        <NewProjectForm org={activeOrgId} />
      )}
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
              <span className="projects__actions">
                <Link
                  className="btn"
                  to={generatePath(surfaceById('matrix').path, {
                    org: activeOrgId,
                    project: project.id,
                  })}
                >
                  Open matrix
                </Link>
                {/* Project settings addresses ONE project, so this is where it
                    is reached from: no static sidebar entry could know which
                    project to mean. */}
                <Link
                  className="btn"
                  aria-label={`Settings for ${project.name}`}
                  to={generatePath(surfaceById('project-settings').path, {
                    org: activeOrgId,
                    project: project.id,
                  })}
                >
                  Settings
                </Link>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * NewProjectForm creates a project in the active organisation.
 *
 * Success and refusal never rest on colour: the created row is announced
 * through `role="status"` and a refusal is `role="alert"` text carrying the
 * glyph, naming the `manage-projects` capability the server checked.
 */
export function NewProjectForm({ org }: { readonly org: string }) {
  const create = useCreateProject(org);
  const nameId = useId();
  const [name, setName] = useState('');

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = name.trim();
    if (trimmed === '') {
      return;
    }
    create.mutate({ name: trimmed }, { onSuccess: () => setName('') });
  };

  return (
    <form className="projects__new" onSubmit={onSubmit} noValidate aria-labelledby="new-project-title">
      <h2 id="new-project-title">New project</h2>
      {create.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">!</span>
          <span>{createProjectRefusalText(create.error)}</span>
        </p>
      ) : null}
      {create.isSuccess ? (
        <p role="status">Project {create.data.name} created.</p>
      ) : null}
      <div className="field">
        <label htmlFor={nameId}>Project name</label>
        <input
          id={nameId}
          name="name"
          required
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
      </div>
      <button
        className="btn btn--primary"
        type="submit"
        disabled={create.isPending || name.trim() === ''}
      >
        {create.isPending ? 'Creating…' : 'Create project'}
      </button>
    </form>
  );
}
