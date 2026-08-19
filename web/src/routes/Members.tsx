import { useEffect, useId, useState } from 'react';
import { useParams } from 'react-router';

import {
  blastRadius,
  capabilitiesAt,
  defaultScopeValue,
  expandTemplate,
  grantFailureText,
  grantScopeLabel,
  membershipFailureText,
  membershipRows,
  optionByValue,
  ROLE_TEMPLATES,
  revokeOutcomeText,
  scopeOf,
  scopeOptions,
  scopeValue,
  templatesAt,
  useApplyTemplate,
  useCreateGrants,
  useOrgGrants,
  useRevokeGrant,
  whoCan,
  type Names,
  type ScopeOption,
} from '../api/access.ts';
import type { Grant } from '../api/identities.ts';
import { useSession } from '../api/session.ts';
import { useOrg, useOrgTopology } from '../api/settings.ts';
import { Alert, Done, Explain, JumpIndex, Panel } from './Sections.tsx';
import { useFeedback, useModalDialog } from './useModalDialog.ts';

/**
 * Members & grants (registry surface `members`, #55 + #60; locked prototype
 * app-chrome iteration 15).
 *
 * One surface for the whole organisation, and that is a decision rather than a
 * shortcut: `listOrgGrants` answers org-, project- AND environment-scoped
 * lines in one read, and there is deliberately no `grant.list-env` — "who can
 * reach this environment" has to include the lines above it, so an
 * environment-only listing could only answer a narrower question while looking
 * like the whole one. The project settings surface therefore links here rather
 * than growing a second permission editor.
 *
 * What the listing does NOT contain is stated on the page, not only here:
 * instance-scope grants reach this organisation by inheritance and are absent
 * by design, because revoking an instance operator from a page with no
 * authority over one is a trap.
 */
export function Members() {
  const params = useParams();
  const org = params.org === undefined ? '' : params.org;
  const orgQuery = useOrg(org);
  const grants = useOrgGrants(org);
  const topology = useOrgTopology(org);
  const session = useSession();
  const revoke = useRevokeGrant();
  const feedback = useFeedback(grantFailureText);
  const [modal, setModal] = useState<'none' | 'grant' | 'blast'>('none');

  const orgName = orgQuery.data?.name ?? org;
  const options = scopeOptions(org, orgName, topology.projects);
  const lines = grants.data?.items ?? [];

  const names = {
    org: () => orgName,
    project: (id: string) => topology.projects.find((p) => p.id === id)?.name ?? id,
    environment: (id: string) =>
      topology.projects.flatMap((p) => p.environments).find((e) => e.id === id)?.name ?? id,
  };
  const rows = membershipRows(lines, names);
  const me = session.data === undefined || session.data === null ? '' : session.data.principal.id;

  const [draft, setDraft] = useState<GrantDraft>({
    principal: '',
    capabilities: [],
    template: '',
    mode: 'capabilities',
    scope: '',
  });

  // The safe default is computed from the topology, so it can only settle once
  // the environments — and their protection — have actually been read.
  useEffect(() => {
    if (modal === 'grant' && topology.ready && draft.scope === '' && options.length > 0) {
      const safe = defaultScopeValue(options);
      if (safe !== '') {
        setDraft((current) => (current.scope === '' ? { ...current, scope: safe } : current));
      }
    }
  }, [draft.scope, modal, options, topology.ready]);

  const onRevoke = (grant: Grant) => {
    feedback.clear();
    revoke.mutate(
      { grant },
      {
        onSuccess: async () => {
          const refreshed = await grants.refetch();
          if (refreshed.data === undefined || refreshed.isError) {
            feedback.ok(
              `The revoke was accepted, but the membership listing could not be refreshed. Reload before deciding whether ${grant.capability} remains effective.`,
            );
            return;
          }
          const address = scopeValue(scopeOf(grant));
          const survivor = refreshed.data.items.find(
            (candidate) =>
              candidate.principal_id === grant.principal_id &&
              candidate.capability === grant.capability &&
              scopeValue(scopeOf(candidate)) === address,
          );
          feedback.ok(revokeOutcomeText(grant, survivor, names));
        },
        onError: feedback.report,
      },
    );
  };

  return (
    <div className="page">
      <h1>Members</h1>
      <p className="page__lede">
        One row per member per scope. Each capability is still its own revocable grant: roles are
        templates that expand when they are applied, so revoking one chip never drags a bundle with
        it.
      </p>

      <JumpIndex
        sections={[
          { id: 'members-inspect', label: 'Who can…?' },
          { id: 'members-list', label: 'Members' },
        ]}
      />

      {grants.isError ? (
        <Alert>{membershipFailureText(grants.error)}</Alert>
      ) : null}
      {orgQuery.isError ? (
        <Alert>The organisation could not be read. Reload before managing its grants.</Alert>
      ) : null}
      {feedback.failure !== null ? <Alert>{feedback.failure}</Alert> : null}
      {feedback.done !== null ? <Done>{feedback.done}</Done> : null}

      <Inspect
        options={options}
        grants={lines}
        names={names}
        grantsPending={grants.isPending}
        grantsSucceeded={grants.isSuccess}
      />

      <Panel id="members-list" title="Members">
        <p>
          Every grant line scoped inside {orgName}. Instance-scope grants reach this organisation by
          inheritance and are deliberately absent: this page has no authority over an instance
          operator, so it does not offer to revoke one.
        </p>

        {grants.isSuccess && rows.length === 0 ? (
          <p role="status">
            No grants inside this organisation yet. Everyone reaching it does so from instance scope.
          </p>
        ) : null}

        {rows.length === 0 ? null : (
          <table className="grants">
            <caption className="visually-hidden">
              Members of {orgName}, one row per principal and scope
            </caption>
            <thead>
              <tr>
                <th scope="col">Member</th>
                <th scope="col">Scope</th>
                <th scope="col">Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <td>
                    <span className="mono">{row.principal}</span>
                    {row.principal === me ? <span className="badge">you</span> : null}
                  </td>
                  <td>
                    <span className={row.level === 'org' ? 'chip chip--wide' : 'chip'}>
                      {row.scopeLabel}
                    </span>
                  </td>
                  <td>
                    <ul className="capabilities">
                      {row.grants.map((grant) => (
                        <li key={grant.id} className="capability">
                          <span className="capability__name mono">{grant.capability}</span>
                          {/* Origin chips per capability line: the SCIM
                              amendment's own requirement, and the one thing
                              that tells a break-glass grant from an ordinary
                              one after an incident. */}
                          {grant.origins.map((origin) => (
                            <span
                              className="badge"
                              key={`${origin.kind}:${origin.subject}`}
                            >
                              {origin.kind}: {origin.subject}
                            </span>
                          ))}
                          <button
                            type="button"
                            className="btn btn--quiet"
                            disabled={revoke.isPending}
                            aria-label={`Revoke ${grant.capability} on ${row.scopeLabel} for ${row.principal}`}
                            onClick={() => onRevoke(grant)}
                          >
                            Revoke
                          </button>
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="panel__actions">
          {topology.isPending ? (
            <p role="status">Loading the complete organisation topology before a new grant can open…</p>
          ) : topology.isError ? (
            <Alert>The organisation topology could not be read completely. Reload before granting anything.</Alert>
          ) : null}
          <button
            type="button"
            className="btn btn--primary"
            disabled={!topology.ready}
            onClick={() => {
              feedback.clear();
              setDraft(freshDraft(options));
              setModal('grant');
            }}
          >
            New grant
          </button>
        </div>
        {/* The prototype's second action here is "invite member". It is not
            built and not stubbed: there is no invitation anywhere in the
            contract — no table, no claim flow, no delivery channel, no expiry
            — and a button that opened a form nothing could submit would be a
            worse answer than its absence (#55 scope cut 1). */}
      </Panel>

      {modal === 'none' ? null : (
        <GrantModal
          orgName={orgName}
          options={options}
          draft={draft}
          stage={modal}
          projects={topology.projects}
          topologyReady={topology.ready}
          topologyPending={topology.isPending}
          topologyError={topology.isError}
          known={[...new Set(lines.map((line) => line.principal_id))]}
          onDraft={setDraft}
          onStage={setModal}
          onDone={(text) => {
            feedback.ok(text);
            setModal('none');
          }}
        />
      )}
    </div>
  );
}

// --- who can …? -------------------------------------------------------------

function Inspect({
  options,
  grants,
  names,
  grantsPending,
  grantsSucceeded,
}: {
  options: readonly ScopeOption[];
  grants: readonly Grant[];
  names: Names;
  grantsPending: boolean;
  grantsSucceeded: boolean;
}) {
  const capabilityId = useId();
  const scopeId = useId();
  const [capability, setCapability] = useState('reveal');
  const [scope, setScope] = useState('');

  const chosen = optionByValue(options, scope) ?? options[0];
  const answer = chosen === undefined ? [] : whoCan(grants, capability, chosen.scope);

  return (
    <Panel id="members-inspect" title="Who can…?">
      <p>
        Answered by inspection over the lines below, including the ones ABOVE the scope you pick:
        grants inherit downward, so an organisation-scoped grant answers for every environment in
        it.
      </p>
      <div className="inspect">
        <div className="field">
          <label htmlFor={capabilityId}>Capability</label>
          <select
            id={capabilityId}
            value={capability}
            onChange={(event) => setCapability(event.target.value)}
          >
            {capabilitiesAt('org').map((atom) => (
              <option key={atom.id} value={atom.id}>
                {atom.id}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={scopeId}>On</label>
          <select
            id={scopeId}
            value={chosen === undefined ? '' : chosen.value}
            onChange={(e) => setScope(e.target.value)}
          >
            {options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>
      {!grantsSucceeded ? (
        grantsPending ? (
          <p className="inspect__answer" role="status">
            Loading grants before answering who can reach this scope…
          </p>
        ) : null
      ) : (
        <p className="inspect__answer" role="status">
        {chosen === undefined ? (
          'This organisation holds no scope to inspect yet.'
        ) : answer.length === 0 ? (
          <>
            <strong>Nobody</strong> holds <span className="mono">{capability}</span> on{' '}
            {chosen.label} through a grant inside this organisation. An instance-scope holder would
            not appear here.
          </>
        ) : (
          <>
            <strong>{answer.length}</strong> grant {answer.length === 1 ? 'line' : 'lines'} give{' '}
            <span className="mono">{capability}</span> on {chosen.label}:{' '}
            {answer
              .map((grant) => `${grant.principal_id} (via ${grantScopeLabel(grant, names)})`)
              .join(', ')}
            .
          </>
        )}
        </p>
      )}
    </Panel>
  );
}

// --- the grant modal --------------------------------------------------------

type GrantDraft = {
  principal: string;
  capabilities: string[];
  template: string;
  mode: 'capabilities' | 'template';
  scope: string;
};

function freshDraft(options: readonly ScopeOption[]): GrantDraft {
  return {
    principal: '',
    capabilities: [],
    template: '',
    mode: 'capabilities',
    scope: defaultScopeValue(options),
  };
}

/**
 * GrantModal is the composition and its org-scope warning, in one component so
 * that "back, change scope" PRESERVES what was composed.
 *
 * That was iteration 13's fix and it is not cosmetic: a warning that threw the
 * composition away would train people to click through it, which is the exact
 * opposite of what a blast-radius warning is for.
 */
function GrantModal({
  orgName,
  options,
  draft,
  stage,
  projects,
  topologyReady,
  topologyPending,
  topologyError,
  known,
  onDraft,
  onStage,
  onDone,
}: {
  orgName: string;
  options: readonly ScopeOption[];
  draft: GrantDraft;
  stage: 'grant' | 'blast';
  projects: ReturnType<typeof useOrgTopology>['projects'];
  topologyReady: boolean;
  topologyPending: boolean;
  topologyError: boolean;
  known: readonly string[];
  onDraft: (draft: GrantDraft) => void;
  onStage: (stage: 'none' | 'grant' | 'blast') => void;
  onDone: (text: string) => void;
}) {
  const dialog = useModalDialog();
  const [failure, setFailure] = useState<string | null>(null);
  const create = useCreateGrants();
  const applyTemplate = useApplyTemplate();
  const principalId = useId();
  const scopeId = useId();
  const templateId = useId();

  const chosen = optionByValue(options, draft.scope);
  const atoms = chosen === undefined ? [] : capabilitiesAt(chosen.level);
  const templates = chosen === undefined ? [] : templatesAt(chosen.level);
  const mutationPending = create.isPending || applyTemplate.isPending;
  const submitBlocked = mutationPending || !topologyReady;

  const selectedTemplate = ROLE_TEMPLATES.find((template) => template.id === draft.template);
  const composed =
    draft.mode === 'template' && selectedTemplate !== undefined && chosen !== undefined
      ? expandTemplate(selectedTemplate.id, chosen.level).join(', ')
      : draft.capabilities.join(', ');

  const submit = () => {
    setFailure(null);
    if (draft.principal.trim() === '') {
      setFailure('Name the principal this grant is for: a human or a service-account id.');
      return;
    }
    if (chosen === undefined) {
      setFailure(
        'Choose a scope. Nothing is preselected when no environment could be confirmed unprotected.',
      );
      return;
    }
    if (!topologyReady && topologyPending) {
      setFailure(
        'The organisation topology is still loading. Wait for every project and environment before confirming this scope.',
      );
      return;
    }
    if (!topologyReady && topologyError) {
      setFailure('The organisation topology could not be read completely. Reload before granting anything.');
      return;
    }
    if (!topologyReady) {
      setFailure('The organisation topology is not ready. Reload before granting anything.');
      return;
    }
    if (draft.mode === 'capabilities' && draft.capabilities.length === 0) {
      setFailure('Pick at least one capability. Each one becomes its own revocable line.');
      return;
    }
    if (draft.mode === 'template' && draft.template === '') {
      setFailure('Pick a role template, or switch back to choosing capabilities.');
      return;
    }
    if (chosen.level === 'org' && stage !== 'blast') {
      onStage('blast');
      return;
    }
    perform();
  };

  const perform = () => {
    if (chosen === undefined) {
      return;
    }
    const scope = chosen.scope;
    const principal = draft.principal.trim();
    if (draft.mode === 'template') {
      applyTemplate.mutate(
        { scope, principal, template: draft.template },
        {
          onSuccess: (result) =>
            onDone(
              `Applied ${draft.template} to ${principal} on ${chosen.label}: ${result.count} independent grant ${result.count === 1 ? 'line' : 'lines'}, each revocable on its own.`,
            ),
          onError: (error) => {
            onStage('grant');
            setFailure(grantFailureText(error));
          },
        },
      );
      return;
    }
    create.mutate(
      { scope, principal, capabilities: draft.capabilities },
      {
        onSuccess: (done) =>
          onDone(
            `Granted ${done.join(', ')} to ${principal} on ${chosen.label}. ${done.length === 1 ? 'It is' : 'They are'} separate lines and revocable one at a time.`,
          ),
        onError: (error) => {
          onStage('grant');
          setFailure(grantFailureText(error));
        },
      },
    );
  };

  if (stage === 'blast') {
    return (
      <dialog
        className="ceremony blast"
        ref={dialog}
        aria-labelledby="blast-title"
        onCancel={(event) => {
          event.preventDefault();
          if (!mutationPending) {
            onStage('none');
          }
        }}
      >
        <h2 id="blast-title">Organisation-scoped grant: check the blast radius</h2>
        <p className="ceremony__lede">
          <strong>{draft.principal}</strong> would get <span className="mono">{composed}</span> on{' '}
          <strong>every project and environment in {orgName}</strong>, current and future. Grants
          inherit downward and there are no deny rules, so there is no per-project exception under
          an organisation grant.
        </p>
        {topologyPending ? (
          <p role="status" aria-live="polite">
            Loading every project, environment, and protection state before showing the blast radius…
          </p>
        ) : topologyError ? (
          <Alert>The full organisation topology could not be read. Reload before confirming this grant.</Alert>
        ) : (
          <ul className="blast__list" aria-label="What an organisation-scoped grant reaches">
            {blastRadius(projects).map((line) => (
              <li key={line.project}>
                <span className="blast__project">{line.project}</span>
                <span className="blast__envs">{line.environments}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="ceremony__cap" role="status">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            Narrower option: grant on one project, or on one environment. Production protection
            rests on granting narrowly, not on the protected flag alone.
          </span>
        </p>
        {failure !== null ? <Alert>{failure}</Alert> : null}
        <div className="ceremony__actions">
          <button type="button" className="btn" disabled={mutationPending} onClick={() => onStage('none')}>
            Cancel
          </button>
          <button type="button" className="btn" disabled={mutationPending} onClick={() => onStage('grant')}>
            Back, change scope
          </button>
          <button type="button" className="btn btn--danger" disabled={submitBlocked} onClick={perform}>
            Grant at organisation scope
          </button>
        </div>
      </dialog>
    );
  }

  return (
    <dialog
      className="ceremony grant-modal"
      ref={dialog}
      aria-labelledby="grant-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!mutationPending) {
          onStage('none');
        }
      }}
    >
      <h2 id="grant-title">New grant</h2>
      <p className="ceremony__lede">
        Pick any number of capabilities: each becomes its <strong>own revocable line</strong> at this
        scope, never a bundle. A role template does exactly this with a preset list.
      </p>

      {failure !== null ? <Alert>{failure}</Alert> : null}
      {topologyPending ? (
        <p role="status" aria-live="polite">
          Loading every project, environment, and protection state before a grant can be submitted…
        </p>
      ) : topologyError ? (
        <Alert>The organisation topology could not be read completely. Reload before granting anything.</Alert>
      ) : null}

      <div className="field">
        <label htmlFor={principalId}>Principal</label>
        <input
          id={principalId}
          list={`${principalId}-known`}
          value={draft.principal}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onDraft({ ...draft, principal: event.target.value })}
        />
        <datalist id={`${principalId}-known`}>
          {known.map((id) => (
            <option key={id} value={id} />
          ))}
        </datalist>
        <p className="field__hint">
          The principal id of a person or a service account; the list offers the ones already
          holding something here. There is no invitation flow in this version, so an account exists
          before it can hold a grant.
        </p>
      </div>

      <fieldset className="grant-modal__mode">
        <legend>What to grant</legend>
        <label className="chk">
          <input
            type="radio"
            name="grant-mode"
            checked={draft.mode === 'capabilities'}
            onChange={() => onDraft({ ...draft, mode: 'capabilities' })}
          />
          <span>Choose capabilities</span>
        </label>
        <label className="chk">
          <input
            type="radio"
            name="grant-mode"
            checked={draft.mode === 'template'}
            onChange={() => onDraft({ ...draft, mode: 'template' })}
          />
          <span>Apply a role template</span>
        </label>
      </fieldset>

      {draft.mode === 'capabilities' ? (
        <ul className="capgrid" aria-label="Capabilities to grant">
          {atoms.map((atom) => (
            <li className="capitem" key={atom.id}>
              <label className="chk">
                <input
                  type="checkbox"
                  checked={draft.capabilities.includes(atom.id)}
                  onChange={(event) =>
                    onDraft({
                      ...draft,
                      capabilities: event.target.checked
                        ? [...draft.capabilities, atom.id]
                        : draft.capabilities.filter((id) => id !== atom.id),
                    })
                  }
                />
                <span className="mono">{atom.id}</span>
              </label>
              <Explain label={atom.id} text={atom.covers} />
            </li>
          ))}
        </ul>
      ) : (
        <div className="field">
          <label htmlFor={templateId}>Role template</label>
          <select
            id={templateId}
            value={draft.template}
            onChange={(event) => onDraft({ ...draft, template: event.target.value })}
          >
            <option value="">Choose a template…</option>
            {templates.map((template) => (
              <option key={template.id} value={template.id}>
                {template.id}
              </option>
            ))}
          </select>
          <p className="field__hint">
            {draft.template === '' || selectedTemplate === undefined || chosen === undefined
              ? 'A template is expanded by the server at grant time; what lands is grants.'
              : `Seeds: ${expandTemplate(selectedTemplate.id, chosen.level).join(', ')}.`}
          </p>
        </div>
      )}

      <div className="field">
        <label htmlFor={scopeId}>Scope</label>
        <select
          id={scopeId}
          value={draft.scope}
          onChange={(event) => {
            const next = optionByValue(options, event.target.value);
            if (next === undefined) {
              onDraft({ ...draft, scope: '', capabilities: [], template: '' });
              return;
            }
            onDraft({
              ...draft,
              scope: next.value,
              capabilities: draft.capabilities.filter((id) =>
                capabilitiesAt(next.level).some((atom) => atom.id === id),
              ),
              template: templatesAt(next.level).some((template) => template.id === draft.template)
                ? draft.template
                : '',
            });
          }}
        >
          <option value="">Choose a scope…</option>
          {[...new Set(options.map((option) => option.group))].map((group) => (
            <optgroup key={group} label={group}>
              {options
                .filter((option) => option.group === group)
                .map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
            </optgroup>
          ))}
        </select>
        <p className="field__hint">
          Narrowest first. A protected environment is last in its project and is never preselected;
          an organisation scope reaches every project, current and future.
        </p>
      </div>

      <div className="ceremony__actions">
        <button type="button" className="btn" disabled={mutationPending} onClick={() => onStage('none')}>
          Cancel
        </button>
        <button type="button" className="btn btn--primary" disabled={submitBlocked} onClick={submit}>
          {mutationPending ? 'Granting…' : 'Grant'}
        </button>
      </div>
    </dialog>
  );
}
