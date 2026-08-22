import { useEffect, useId, useState } from 'react';
import { generatePath, Link, useParams } from 'react-router';

import { useOrgGrants } from '../api/access.ts';
import {
  retentionBoundsPayload,
  retentionDayState,
  retentionSentence,
  settingsFailureText,
  settingsOperationFailure,
  useDeleteOrg,
  useOrg,
  useOrgRetention,
  useProjectRetentions,
  useProjects,
  useRenameOrg,
  useSetOrgRetention,
  type RetentionPolicy,
  type RetentionDayState,
  type SettingsOperation,
} from '../api/settings.ts';
import { surfaceById } from '../app/navigation.ts';
import { notifySuccess } from '../app/notifications.tsx';
import { Alert, Done, JumpIndex, Panel, TypedNameConfirm } from './Sections.tsx';
import { useFeedback } from './useModalDialog.ts';

/**
 * Organisation settings (registry surface `org-settings`, #60; locked
 * prototype app-chrome iteration 14, retention panel from iteration 16).
 *
 * The one thing to know before reading the identity panel: renaming and
 * deleting an organisation carry `instance-config@instance`, because the
 * locked capability set holds NO org-lifecycle atom (`manage-projects` is
 * explicitly "create and delete projects"). An organisation administrator
 * therefore cannot rename or delete the organisation they administer and gets
 * the uniform 404 — a standing consequence #48 and #55 both carried to human
 * disposition rather than amending the ADR in code. The surface states it in
 * the panel instead of discovering it as a mysterious refusal.
 *
 * The identity panel is also where the prototype's hue picker, glyph picker
 * and image upload are NOT: no operation anywhere in the contract stores any
 * of them, and an avatar that survived only until reload would be a lie about
 * what was saved.
 */
export function OrgSettings() {
  const params = useParams();
  const org = params.org === undefined ? '' : params.org;
  const orgQuery = useOrg(org);
  const retention = useOrgRetention(org);
  const grants = useOrgGrants(org);
  const projects = useProjects(org);
  const projectPolicies = useProjectRetentions(
    org,
    projects.isSuccess ? projects.data.items : [],
  );
  const rename = useRenameOrg();
  const remove = useDeleteOrg(() =>
    notifySuccess('Organisation deleted. Sign in again to continue.'),
  );
  const setRetention = useSetOrgRetention(org);
  const nameId = useId();

  const [name, setName] = useState('');
  const feedback = useFeedback(settingsFailureText);

  const current = orgQuery.data;
  useEffect(() => {
    setName('');
  }, [org]);
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
      <h1>Organisation settings</h1>
      <p className="page__lede">
        Identity, the retention cap every project inherits, and the lifecycle. Access lives on its
        own surface; the danger zone is deliberately last.
      </p>

      <JumpIndex
        sections={[
          { id: 'org-identity', label: 'Identity' },
          { id: 'org-retention', label: 'Retention' },
          { id: 'org-members', label: 'Members' },
          { id: 'org-danger', label: 'Danger zone' },
        ]}
      />

      {orgQuery.isError ? (
        <Alert>
          This organisation could not be read. It may not exist, or it may not be yours to
          administer — the two answers are deliberately the same.
        </Alert>
      ) : null}
      {feedback.failure !== null ? <Alert>{feedback.failure}</Alert> : null}
      {feedback.done !== null ? <Done>{feedback.done}</Done> : null}

      <Panel id="org-identity" title="Identity">
        <dl className="kv">
          <div className="kv__pair">
            <dt>Identifier</dt>
            <dd className="mono">{org}</dd>
          </div>
          <div className="kv__pair">
            <dt>Created</dt>
            <dd>
              {current === undefined ? '—' : new Date(current.created_at).toLocaleString()}
            </dd>
          </div>
          <div className="kv__pair">
            <dt>State</dt>
            <dd>
              {current === undefined ? '—' : current.active ? 'active' : 'inactive'}
            </dd>
          </div>
        </dl>
        <div className="field">
          <label htmlFor={nameId}>Name</label>
          <input
            id={nameId}
            value={name}
            disabled={current === undefined}
            onChange={(event) => setName(event.target.value)}
          />
          <p className="field__hint">
            Renaming an organisation is instance-operator work: the permission model has no
            org-lifecycle capability, so an organisation administrator is refused here with the same
            answer a missing organisation gets.
          </p>
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
                { org, name },
                {
                  onSuccess: (result) => feedback.ok(`Renamed to ${result.name}.`),
                  onError: (error) => report('rename-org', error),
                },
              )
            }
          >
            Rename
          </button>
        </div>
      </Panel>

      <Panel id="org-retention" title="Retention">
        <p>
          The cap every project in this organisation inherits, and the ceiling no project override
          may exceed. Payload collection is what this bounds; who changed what is permanent.
        </p>
        {retention.isError ? (
          <Alert>The retention policy could not be read for this organisation.</Alert>
        ) : null}
        {retention.data === undefined ? null : (
          <RetentionEditor
            key={org}
            policy={retention.data}
            busy={setRetention.isPending}
            onSave={(next) =>
              setRetention.mutate(next, {
                onSuccess: (saved) =>
                  feedback.ok(`Retention saved. ${retentionSentence(saved)}`),
                onError: (error) => report('set-org-retention', error),
              })
            }
          />
        )}
        <ProjectRetentionList
          org={org}
          projects={projects}
          policies={projectPolicies}
        />
      </Panel>

      <Panel id="org-members" title="Members">
        <p>
          {grants.isSuccess
            ? `${grants.data.count} grant ${grants.data.count === 1 ? 'line' : 'lines'} inside this organisation.`
            : 'The membership listing is read on its own surface, behind its own second factor.'}
        </p>
        <div className="panel__actions">
          <Link className="btn" to={generatePath(surfaceById('members').path, { org })}>
            Open members
          </Link>
        </div>
        <p className="field__hint">
          Entry point only: granting, revoking and inspection live on the members surface, so there
          is exactly one permission editor.
        </p>
      </Panel>

      <Panel id="org-danger" title="Danger zone" danger>
        <TypedNameConfirm
          key={current === undefined ? `pending-${org}` : current.id}
          label="Delete this organisation"
          expect={current === undefined ? null : current.name}
          action="Delete organisation"
          busy={remove.isPending}
          hint={
            <>
              Deletion never cascades into projects or their contents. Authority scoped inside an
              otherwise empty organisation is removed with it, and affected sessions are revoked.
            </>
          }
          onConfirm={() =>
            remove.mutate(
              { org },
              {
                onError: (error) => report('delete-org', error),
              },
            )
          }
        />
      </Panel>
    </div>
  );
}

function ProjectRetentionList({
  org,
  projects,
  policies,
}: {
  org: string;
  projects: ReturnType<typeof useProjects>;
  policies: ReturnType<typeof useProjectRetentions>;
}) {
  return (
    <div className="project-retention-list">
      <h3>Project policies</h3>
      {projects.isPending ? <p role="status">Loading project retention policies…</p> : null}
      {projects.isError ? (
        <Alert>Projects could not be read, so their retention policies are unavailable.</Alert>
      ) : null}
      {projects.isSuccess && projects.data.items.length === 0 ? (
        <p role="status">This organisation has no projects.</p>
      ) : null}
      {projects.isSuccess ? (
        <ul className="project-retention-list__items">
          {projects.data.items.map((project) => {
            const state = policies.get(project.id);
            return (
              <li key={project.id}>
                <div>
                  <strong>{project.name}</strong>
                  {state === undefined || state.status === 'pending' ? (
                    <span role="status">Loading effective bounds…</span>
                  ) : state.status === 'error' ? (
                    <span className="alert" role="alert">
                      This project&apos;s retention policy could not be read.
                    </span>
                  ) : (
                    <span>
                      {state.policy.inherited ? 'inherits → ' : 'custom — '}
                      {retentionSentence(state.policy)}
                    </span>
                  )}
                </div>
                <Link
                  className="btn"
                  aria-label={`Settings for ${project.name}`}
                  to={generatePath(surfaceById('project-settings').path, {
                    org,
                    project: project.id,
                  })}
                >
                  Project settings
                </Link>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}

/**
 * RetentionEditor is the org cap in the API's own two dimensions.
 *
 * The prototype drew one number ("keep last N revisions") because it predates
 * the retention ticket. The real policy is `keep-if-either`: a payload
 * survives while it is young enough OR recent enough, so a UI with one field
 * would have to hide a bound the operator is accountable for. `unlimited` is
 * explicit organisation state, never a missing value.
 */
function RetentionEditor({
  policy,
  busy,
  onSave,
}: {
  policy: RetentionPolicy;
  busy: boolean;
  onSave: (next: RetentionPolicy) => void;
}) {
  const modeId = useId();
  const ageId = useId();
  const countId = useId();
  const [mode, setMode] = useState(policy.mode);
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
    setMode(policy.mode);
    setAge(retentionDayState(policy.max_age_seconds));
    setCount(
      policy.last_revisions === null || policy.last_revisions === undefined
        ? ''
        : String(policy.last_revisions),
    );
    setRefusal(null);
  }, [policy.last_revisions, policy.max_age_seconds, policy.mode]);

  return (
    <>
      <p className="retention__current" role="status">
        {retentionSentence(policy)}
      </p>
      {mode === 'keep-if-either' && age.kind === 'exact' ? (
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
      {mode === 'keep-if-either' && age.kind === 'absent' ? (
        <p role="status">No maximum age is present. Enter a whole-day replacement deliberately.</p>
      ) : null}
      {refusal === null ? null : <Alert>{refusal}</Alert>}
      <div className="field">
        <label htmlFor={modeId}>Mode</label>
        <select
          id={modeId}
          value={mode}
          onChange={(event) => {
            setRefusal(null);
            setMode(modeOf(event.target.value));
          }}
        >
          <option value="keep-if-either">keep-if-either (bounded)</option>
          <option value="unlimited">unlimited (never collect)</option>
        </select>
      </div>
      {mode === 'keep-if-either' ? (
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
      ) : (
        <p className="field__hint">
          Unlimited is the only policy a project cannot copy: a project override is always bounded.
        </p>
      )}
      <div className="panel__actions">
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() => {
            if (mode === 'unlimited') {
              setRefusal(null);
              onSave({ mode, max_age_seconds: null, last_revisions: null });
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
            onSave({
              mode,
              max_age_seconds: payload.maxAgeSeconds,
              last_revisions: payload.lastRevisions,
            });
          }}
        >
          Save retention
        </button>
      </div>
    </>
  );
}

function modeOf(value: string): 'keep-if-either' | 'unlimited' {
  if (value === 'keep-if-either' || value === 'unlimited') {
    return value;
  }
  throw new Error(`unknown retention mode ${value}`);
}
