import { useEffect, useId, useState } from 'react';
import { generatePath, Link, useParams } from 'react-router';

import {
  projectRetentionInherited,
  retentionBoundsPayload,
  retentionDayState,
  retentionSentence,
  settingsFailureText,
  settingsOperationFailure,
  useDeleteProject,
  useEnvironmentSettings,
  useEnvironments,
  useOrgRetention,
  useProject,
  useProjectRetention,
  useRenameProject,
  useSetEnvironmentSettings,
  useSetProjectRetention,
  type EnvironmentSettingsReadState,
  type ProjectRetentionPolicy,
  type RetentionDayState,
  type SettingsOperation,
} from '../api/settings.ts';
import { surfaceById } from '../app/navigation.ts';
import { Alert, Done, JumpIndex, Panel, TypedNameConfirm } from './Sections.tsx';
import { useFeedback } from './useModalDialog.ts';

/**
 * Project settings (registry surface `project-settings`, #60; locked prototype
 * app-chrome iteration 15, retention panel from iteration 16).
 *
 * Sections: Identity · Policy · Retention · Access · Danger zone. Two of the
 * prototype's are missing, by name rather than by omission:
 *
 *  - **Metadata** (description, icon, hue). The project contract carries id,
 *    org, name and creation time and nothing else — there is no field to write
 *    and no operation to write it with.
 *  - **`definitions_source: db | git`**. The source-of-truth ADR fixes the
 *    switch and the read-only consequence, but no column, service or endpoint
 *    for it exists on this branch (it belongs to the definitions Git flow,
 *    mvp-boundary S4). A select that could not persist would be the one thing
 *    worse than its absence: a security guard that appears to be set and is
 *    not.
 */
export function ProjectSettings() {
  const params = useParams();
  const org = params.org === undefined ? '' : params.org;
  const project = params.project === undefined ? '' : params.project;
  const projectQuery = useProject(org, project);
  const environments = useEnvironments(org, project);
  const orgRetention = useOrgRetention(org);
  const projectRetention = useProjectRetention(org, project);
  const rename = useRenameProject(org);
  const remove = useDeleteProject(org);
  const nameId = useId();

  const [name, setName] = useState('');
  const feedback = useFeedback(settingsFailureText);

  const current = projectQuery.data;
  useEffect(() => {
    setName('');
  }, [org, project]);
  useEffect(() => {
    if (current !== undefined) {
      setName(current.name);
    }
  }, [current]);

  const report = (operation: SettingsOperation, error: unknown) => {
    feedback.report(settingsOperationFailure(operation, error));
  };

  return (
    <div className="page">
      <h1>Project settings</h1>
      <p className="page__lede">
        The guards on the definitions editor live here rather than with the editor they restrain:
        whoever can flip a guard back must not be whoever the guard is aimed at.
      </p>

      <JumpIndex
        sections={[
          { id: 'project-identity', label: 'Identity' },
          { id: 'project-policy', label: 'Policy' },
          { id: 'project-retention', label: 'Retention' },
          { id: 'project-access', label: 'Access' },
          { id: 'project-danger', label: 'Danger zone' },
        ]}
      />

      {projectQuery.isError ? (
        <Alert>
          This project could not be read. It may not exist, or it may not be yours to reach — the
          two answers are deliberately the same.
        </Alert>
      ) : null}
      {feedback.failure !== null ? <Alert>{feedback.failure}</Alert> : null}
      {feedback.done !== null ? <Done>{feedback.done}</Done> : null}

      <Panel id="project-identity" title="Identity">
        <dl className="kv">
          <div className="kv__pair">
            <dt>Identifier</dt>
            <dd className="mono">{project}</dd>
          </div>
          <div className="kv__pair">
            <dt>Organisation</dt>
            <dd className="mono">{org}</dd>
          </div>
          <div className="kv__pair">
            <dt>Created</dt>
            <dd>{current === undefined ? '—' : new Date(current.created_at).toLocaleString()}</dd>
          </div>
        </dl>
        <div className="field">
          <label htmlFor={nameId}>Name</label>
          <input id={nameId} value={name} onChange={(event) => setName(event.target.value)} />
        </div>
        <div className="panel__actions">
          <button
            type="button"
            className="btn"
            disabled={
              current === undefined || rename.isPending || name === '' || name === current.name
            }
            onClick={() =>
              rename.mutate(
                { project, name },
                {
                  onSuccess: (result) => feedback.ok(`Renamed to ${result.name}.`),
                  onError: (error) => report('rename-project', error),
                },
              )
            }
          >
            Rename
          </button>
        </div>
        <p className="field__hint">
          The identifier never moves: it is what every URL, every pin and every audit row already
          names. Renaming changes the label and nothing else.
        </p>
      </Panel>

      <Panel id="project-policy" title="Policy">
        <p>
          Per environment: whether it is protected, and how long one successful reauthentication
          stands for further disclosures. A protected environment caps that window at zero — a
          passkey per disclosure, and a code cannot authorise one.
        </p>
        {environments.isError ? (
          <Alert>This project&apos;s environments could not be read.</Alert>
        ) : null}
        {environments.isPending ? <p role="status">Loading environment policies…</p> : null}
        {environments.isSuccess ? (
          <EnvironmentPolicy
            org={org}
            project={project}
            environments={environments.data.items}
            onDone={feedback.ok}
            onError={(error) => report('set-environment-settings', error)}
          />
        ) : null}
        <p className="field__hint">
          The definitions source (<span className="mono">db</span> or{' '}
          <span className="mono">git</span>) belongs in this panel and is not here: nothing on this
          branch stores it. It arrives with the definitions Git flow.
        </p>
      </Panel>

      <Panel id="project-retention" title="Retention">
        {orgRetention.isPending ? <p role="status">Loading the organisation cap…</p> : null}
        {orgRetention.isError ? (
          <Alert>The organisation retention cap could not be read.</Alert>
        ) : null}
        {orgRetention.isSuccess ? (
          <p>Organisation cap — {retentionSentence(orgRetention.data)}</p>
        ) : null}
        {projectRetention.isError ? (
          <Alert>This project&apos;s retention policy could not be read.</Alert>
        ) : null}
        {projectRetention.data === undefined || orgRetention.data === undefined ? null : (
          <ProjectRetentionEditor
            key={`${org}/${project}`}
            org={org}
            project={project}
            policy={projectRetention.data}
            onDone={feedback.ok}
            onError={(error) => report('set-project-retention', error)}
          />
        )}
      </Panel>

      <Panel id="project-access" title="Access">
        <p>
          Grants on this project and its environments are administered on the organisation&apos;s
          members surface, which lists every depth at once — an environment-only listing would omit
          the grants that reach it from above.
        </p>
        <div className="panel__actions">
          <Link className="btn" to={generatePath(surfaceById('members').path, { org })}>
            Open members
          </Link>
        </div>
      </Panel>

      <Panel id="project-danger" title="Danger zone" danger>
        <TypedNameConfirm
          key={current === undefined ? `pending-${project}` : current.id}
          label="Delete this project"
          expect={current === undefined ? null : current.name}
          action="Delete project"
          busy={remove.isPending}
          hint={
            <>
              Deletion never cascades: a project that still holds any environment is refused. Delete
              its environments first, deliberately and one at a time.
            </>
          }
          onConfirm={() =>
            remove.mutate(
              { project },
              {
                onSuccess: () => feedback.ok('Project deleted.'),
                onError: (error) => report('delete-project', error),
              },
            )
          }
        />
      </Panel>
    </div>
  );
}

/** The reveal-reauthentication windows the surface offers, in seconds. */
const WINDOWS: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'inherit', label: 'inherit the instance default' },
  { value: '0', label: '0 — every disclosure reauthenticates' },
  { value: '300', label: '5 minutes' },
  { value: '900', label: '15 minutes' },
  { value: '3600', label: '60 minutes' },
];

function EnvironmentPolicy({
  org,
  project,
  environments,
  onDone,
  onError,
}: {
  org: string;
  project: string;
  environments: readonly { id: string; name: string }[];
  onDone: (text: string) => void;
  onError: (error: unknown) => void;
}) {
  const protection = useEnvironmentSettings(org, project, environments);
  const save = useSetEnvironmentSettings(org, project);

  if (environments.length === 0) {
    return <p role="status">This project holds no environments yet.</p>;
  }

  return (
    <ul className="envpolicy">
      {environments.map((environment) => (
        <EnvironmentPolicyItem
          key={environment.id}
          environment={environment}
          state={protection.get(environment.id)}
          busy={save.isPending}
          onSave={(next) =>
            save.mutate(
              { environment: environment.id, ...next },
              {
                onSuccess: (saved) =>
                  onDone(
                    saved.protected
                      ? `${environment.name} is protected: its reveal window is capped at 0, so every disclosure takes its own passkey ceremony.`
                      : `${environment.name} is not protected. Its reveal window is ${saved.reauth_window_seconds === null || saved.reauth_window_seconds === undefined ? 'the instance default' : `${saved.reauth_window_seconds} seconds`}.`,
                  ),
                onError,
              },
            )
          }
        />
      ))}
    </ul>
  );
}

function EnvironmentPolicyItem({
  environment,
  state,
  busy,
  onSave,
}: {
  environment: { id: string; name: string };
  state: EnvironmentSettingsReadState | undefined;
  busy: boolean;
  onSave: (next: { protectedFlag: boolean; reauthWindowSeconds: number | null }) => void;
}) {
  if (state === undefined) {
    throw new Error(`environment ${environment.id} has no settings read state`);
  }
  return <EnvironmentRow environment={environment} state={state} busy={busy} onSave={onSave} />;
}

function EnvironmentRow({
  environment,
  state,
  busy,
  onSave,
}: {
  environment: { id: string; name: string };
  state: EnvironmentSettingsReadState;
  busy: boolean;
  onSave: (next: { protectedFlag: boolean; reauthWindowSeconds: number | null }) => void;
}) {
  const protectedId = useId();
  const windowId = useId();
  const [flag, setFlag] = useState(state.status === 'ready' && state.protected);
  const [reauthWindow, setReauthWindow] = useState(
    state.status !== 'ready' ||
      state.reauth_window_seconds === null ||
      state.reauth_window_seconds === undefined
      ? 'inherit'
      : String(state.reauth_window_seconds),
  );

  useEffect(() => {
    if (state.status === 'ready') {
      setFlag(state.protected);
      setReauthWindow(
        state.reauth_window_seconds === null || state.reauth_window_seconds === undefined
          ? 'inherit'
          : String(state.reauth_window_seconds),
      );
    }
  }, [
    state.status,
    state.status === 'ready' ? state.protected : undefined,
    state.status === 'ready' ? state.reauth_window_seconds : undefined,
  ]);

  const ready = state.status === 'ready';
  const windowOptions =
    reauthWindow === 'inherit' || WINDOWS.some((option) => option.value === reauthWindow)
      ? WINDOWS
      : [...WINDOWS, { value: reauthWindow, label: `${reauthWindow} seconds (current)` }];

  return (
    <li className="envpolicy__row">
      <h3>{environment.name}</h3>
      {state.status === 'pending' ? (
        <p role="status">Loading this environment&apos;s policy…</p>
      ) : null}
      {state.status === 'unreadable' ? (
        <p role="status">
          This environment&apos;s policy could not be read, so nothing here claims to know it.
          Reading it needs <span className="mono">read</span> on the environment, which managing
          members does not confer.
        </p>
      ) : null}
      {state.status === 'forbidden' ? (
        <Alert>You are not permitted to read this environment&apos;s policy.</Alert>
      ) : null}
      {state.status === 'error' ? (
        <Alert>This environment&apos;s policy failed to load. Reload to try again.</Alert>
      ) : null}
      <div className="field chk">
        <input
          id={protectedId}
          type="checkbox"
          checked={flag}
          disabled={!ready}
          onChange={(event) => setFlag(event.target.checked)}
        />
        <label htmlFor={protectedId}>Protected environment</label>
      </div>
      <div className="field">
        <label htmlFor={windowId}>Reveal reauthentication window</label>
        <select
          id={windowId}
          value={flag ? '0' : reauthWindow}
          disabled={!ready || flag}
          onChange={(event) => setReauthWindow(event.target.value)}
        >
          {windowOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        {/* Stated, not merely disabled: "protected" and "someone set the
            window to 0" are different sentences, and the human is owed
            whichever one is true. */}
        <p className="field__hint">
          {!ready
            ? 'Save stays disabled until this exact policy has been read.'
            : flag
            ? 'Protected caps this window at 0. The control is fixed there rather than hidden, so the cap is visible as the reason.'
            : 'Inheriting means this environment follows the instance default; 0 means every disclosure reauthenticates, which is a legal setting and not the same statement.'}
        </p>
      </div>
      <div className="panel__actions">
        <button
          type="button"
          className="btn"
          disabled={busy || !ready}
          aria-label={`Save policy for ${environment.name}`}
          onClick={() =>
            onSave({
              protectedFlag: flag,
              reauthWindowSeconds:
                flag ? 0 : reauthWindow === 'inherit' ? null : Number(reauthWindow),
            })
          }
        >
          Save policy
        </button>
      </div>
    </li>
  );
}

/** ProjectRetentionEditor sends the policy to the authoritative cap validator. */
function ProjectRetentionEditor({
  org,
  project,
  policy,
  onDone,
  onError,
}: {
  org: string;
  project: string;
  policy: ProjectRetentionPolicy;
  onDone: (text: string) => void;
  onError: (error: unknown) => void;
}) {
  const save = useSetProjectRetention(org, project);
  const modeId = useId();
  const ageId = useId();
  const countId = useId();
  const [inherited, setInherited] = useState(policy.inherited);
  const [age, setAge] = useState<RetentionDayState>(() =>
    retentionDayState(policy.max_age_seconds),
  );
  const [count, setCount] = useState(
    policy.last_revisions === null || policy.last_revisions === undefined
      ? ''
      : String(policy.last_revisions),
  );
  const [refusal, setRefusal] = useState<string | null>(null);

  useEffect(() => {
    setInherited(policy.inherited);
    setAge(retentionDayState(policy.max_age_seconds));
    setCount(
      policy.last_revisions === null || policy.last_revisions === undefined
        ? ''
        : String(policy.last_revisions),
    );
    setRefusal(null);
  }, [policy.inherited, policy.last_revisions, policy.max_age_seconds]);

  return (
    <>
      <p className="retention__current" role="status">
        {policy.inherited
          ? `This project inherits the organisation cap and follows it when it changes. Effective: ${retentionSentence(policy)}`
          : `This project holds its own override, detached from later organisation changes. Effective: ${retentionSentence(policy)}`}
      </p>
      {!inherited && age.kind === 'exact' ? (
        <Alert>
          Current maximum age is exact ({age.seconds} seconds), not whole days. The day editor is
          disabled so that exact value cannot look absent.
          <button
            type="button"
            className="btn"
            onClick={() => setAge({ kind: 'days', days: '' })}
          >
            Replace with whole days
          </button>
        </Alert>
      ) : null}
      {!inherited && age.kind === 'absent' ? (
        <p role="status">No maximum age is present. Enter a whole-day replacement deliberately.</p>
      ) : null}
      {refusal !== null ? <Alert>{refusal}</Alert> : null}
      <div className="field">
        <label htmlFor={modeId}>Policy</label>
        <select
          id={modeId}
          value={inherited ? 'inherit' : 'override'}
          onChange={(event) => {
            setRefusal(null);
            setInherited(projectRetentionInherited(event.target.value));
          }}
        >
          <option value="inherit">inherit the organisation cap</option>
          <option value="override">override, at or below the cap</option>
        </select>
      </div>
      {inherited ? null : (
        <div className="retention__bounds">
          <div className="field">
            <label htmlFor={ageId}>Maximum age, in days</label>
            <input
              id={ageId}
              type="number"
              min={1}
              inputMode="numeric"
              value={age.kind === 'days' ? age.days : ''}
              disabled={age.kind === 'exact'}
              onChange={(event) => {
                setRefusal(null);
                setAge({ kind: 'days', days: event.target.value });
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={countId}>Revisions kept per environment</label>
            <input
              id={countId}
              type="number"
              min={1}
              inputMode="numeric"
              value={count}
              onChange={(event) => {
                setRefusal(null);
                setCount(event.target.value);
              }}
            />
          </div>
        </div>
      )}
      <div className="panel__actions">
        <button
          type="button"
          className="btn"
          disabled={save.isPending}
          onClick={() => {
            if (inherited) {
              setRefusal(null);
              saveProjectRetention(
                save,
                { inherited: true, maxAgeSeconds: null, lastRevisions: null },
                onDone,
                onError,
              );
              return;
            }
            const payload = retentionBoundsPayload(
              age.kind === 'days' ? age.days : '',
              count,
            );
            if (!payload.ok) {
              setRefusal(payload.message);
              return;
            }
            setRefusal(null);
            saveProjectRetention(
              save,
              {
                inherited: false,
                maxAgeSeconds: payload.maxAgeSeconds,
                lastRevisions: payload.lastRevisions,
              },
              onDone,
              onError,
            );
          }}
        >
          Save retention
        </button>
      </div>
    </>
  );
}

type ProjectRetentionMutation = ReturnType<typeof useSetProjectRetention>;

function saveProjectRetention(
  save: ProjectRetentionMutation,
  input: { inherited: boolean; maxAgeSeconds: number | null; lastRevisions: number | null },
  onDone: (text: string) => void,
  onError: (error: unknown) => void,
): void {
  save.mutate(input, {
    onSuccess: (saved) =>
      onDone(
        saved.inherited
          ? 'Override cleared. This project follows the organisation cap live.'
          : `Override saved. ${retentionSentence(saved)}`,
      ),
    onError,
  });
}
