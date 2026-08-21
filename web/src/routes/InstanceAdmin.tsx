import {
  getCredentialPolicyOp,
  getRetentionHealthOp,
  setCredentialPolicyOp,
} from '@hikyo/operations';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useId, useState } from 'react';
import { generatePath, Link } from 'react-router';

import {
  capabilitiesAt,
  grantFailureText,
  grantOutcomeSummary,
  grantScopeLabel,
  templatesAt,
  useApplyTemplate,
  useCreateGrants,
  useInstanceGrants,
  useRevokeGrant,
} from '../api/access.ts';
import { ApiError, parsed } from '../api/client.ts';
import type { Grant } from '../api/identities.ts';
import { retentionBanner } from '../api/retention.ts';
import {
  settingsFailureText,
  settingsOperationFailure,
  useCreateOrg,
  useInstanceOrgs,
  useRotateTokenKey,
} from '../api/settings.ts';
import { surfaceById } from '../app/navigation.ts';
import { Alert, Done, JumpIndex, Panel } from './Sections.tsx';
import { useFeedback, useModalDialog } from './useModalDialog.ts';

const credentialPolicyKey = ['instance-credential-policy'] as const;
const instanceRetentionKey = ['instance-retention-health'] as const;
function useCredentialPolicy() {
  return useQuery({
    queryKey: credentialPolicyKey,
    queryFn: () => parsed(getCredentialPolicyOp, {}),
    retry: false,
  });
}

function useSetCredentialPolicy() {
  return useMutation({
    mutationFn: (input: { maxFiniteLifetimeSeconds: number; allowIndefinite: boolean; maxLiveCredentials: number; confirm: boolean }) =>
      parsed(setCredentialPolicyOp, {
        body: {
          max_finite_lifetime_seconds: input.maxFiniteLifetimeSeconds,
          allow_indefinite: input.allowIndefinite,
          max_live_credentials: input.maxLiveCredentials,
          ...(input.confirm ? { confirm: true } : {}),
        },
      }),
  });
}

function useInstanceRetentionHealth() {
  return useQuery({
    queryKey: instanceRetentionKey,
    queryFn: () => parsed(getRetentionHealthOp, {}),
    retry: false,
  });
}

const secondFactor = (error: unknown) => error instanceof ApiError && error.status === 403;
const nondisclosed = (error: unknown) => error instanceof ApiError && error.status === 404;
class SurfaceMessage extends Error {}
const instanceFailureText = (error: unknown) =>
  error instanceof SurfaceMessage
    ? error.message
    : settingsFailureText(error, 'set-credential-policy');

export function InstanceAdmin() {
  const orgs = useInstanceOrgs();
  const grants = useInstanceGrants();
  const health = useInstanceRetentionHealth();
  const policy = useCredentialPolicy();
  const create = useCreateOrg();
  const createGrants = useCreateGrants();
  const applyTemplate = useApplyTemplate();
  const revokeGrant = useRevokeGrant();
  const rotate = useRotateTokenKey();
  const nameId = useId();
  const principalId = useId();
  const { failure, done, report, ok } = useFeedback(instanceFailureText);
  const [name, setName] = useState('');
  const [confirmRotate, setConfirmRotate] = useState(false);
  const rotationFeedback = useFeedback((error) => settingsFailureText(error, 'rotate-token-key'));
  const [grantPrincipal, setGrantPrincipal] = useState('');
  const [grantTemplate, setGrantTemplate] = useState('');
  const [selectedCapabilities, setSelectedCapabilities] = useState<readonly string[]>([]);
  const instanceCapabilities = capabilitiesAt('instance');
  const instanceTemplates = templatesAt('instance');
  const stale = retentionBanner(health.data, health.isError);

  const revoke = (grant: Grant) => revokeGrant.mutate({ grant }, {
    onSuccess: async () => {
      const refreshed = await grants.refetch();
      if (refreshed.isError) return report(refreshed.error);
      const remains = refreshed.data?.items.some((candidate) => candidate.principal_id === grant.principal_id && candidate.capability === grant.capability);
      ok(remains === true
        ? `Released the revocable origin for ${grant.capability}; another origin still holds the grant.`
        : `Revoked ${grant.capability} from ${grant.principal_id}; the refreshed list confirms it is absent.`);
    },
    onError: (error) => report(new SurfaceMessage(grantFailureText(error))),
  });

  return <div className="page">
    <h1>Instance administration</h1>
    <p className="page__lede">Instance-scope work, evaluated by the same grants and recorded in the same trail as the CLI verbs it mirrors. Nothing here is UI-special.</p>
    <JumpIndex sections={[
      { id: 'instance-orgs', label: 'Organisations' },
      { id: 'instance-grants', label: 'Instance grants' },
      { id: 'instance-settings', label: 'Instance settings' },
      { id: 'instance-retention', label: 'Retention health' },
      { id: 'instance-keys', label: 'Keys & crypto' },
    ]} />
    {failure !== null ? <Alert>{failure}</Alert> : null}
    {done !== null ? <Done>{done}</Done> : null}

    <Panel id="instance-orgs" title="Organisations">
      <p className="machine__lede">
        Creating an organisation grants nobody anything, including its creator. To work inside one,
        add a grant under Instance grants below (your principal ID is on Account &amp; security; the
        admin template covers the organisation) or in the organisation&apos;s Members page once you
        hold manage-members there. A grant on your own account ends the current session.
      </p>
      {orgs.isPending ? <p role="status">Loading organisations…</p> : null}
      {secondFactor(orgs.error) ? <Alert>Listing every organisation on this instance needs a second factor. This session does not have sufficient second-factor assurance; present your authenticator code or passkey in the banner above.</Alert> : null}
      {nondisclosed(orgs.error) ? <p role="status">The organisation directory is not disclosed to this session.</p> : null}
      {orgs.isError && !secondFactor(orgs.error) && !nondisclosed(orgs.error) ? <Alert>{settingsFailureText(orgs.error, 'list-instance-orgs')}</Alert> : null}
      {orgs.isSuccess ? <>
        <p role="status">{orgs.data.count} {orgs.data.count === 1 ? 'organisation' : 'organisations'} on this instance.</p>
        <ul className="factors">{orgs.data.items.map((org) => <li className="factor" key={org.id}>
          <div><strong>{org.name}</strong><span className="factor__meta mono">{org.id} · {org.active ? 'active' : 'inactive'} · created {new Date(org.created_at).toLocaleDateString()}</span></div>
          <Link className="btn" to={generatePath(surfaceById('org-settings').path, { org: org.id })}>Settings</Link>
        </li>)}</ul>
      </> : null}
      <div className="field"><label htmlFor={nameId}>New organisation name</label><input id={nameId} value={name} onChange={(event) => setName(event.target.value)} /></div>
      <div className="panel__actions"><button type="button" className="btn btn--primary" disabled={create.isPending || name.trim() === ''} onClick={() => create.mutate({ name: name.trim() }, {
        onSuccess: (org) => { setName(''); ok(`Created ${org.name}. Creating an organisation seeds its creator nothing — grant somebody membership before it can be administered from inside.`); },
        onError: (error) => report(settingsOperationFailure('create-org', error)),
      })}>Create organisation</button></div>
    </Panel>

    <Panel id="instance-grants" title="Instance grants">
      <p>Grants written at instance scope inherit downward into every organisation. Each origin and its subject remain visible so incident provenance is not reduced to a colour.</p>
      {grants.isPending ? <p role="status">Loading instance grants…</p> : null}
      {secondFactor(grants.error) ? <Alert>Instance grants require a second factor.</Alert> : null}
      {nondisclosed(grants.error) ? <p role="status">Instance grants are not disclosed to this session.</p> : null}
      {grants.isError && !secondFactor(grants.error) && !nondisclosed(grants.error) ? <Alert>{grantFailureText(grants.error)}</Alert> : null}
      {grants.isSuccess && grants.data.items.length === 0 ? <p role="status">No instance-scope grants.</p> : null}
      <ul className="factors">{grants.isSuccess ? grants.data.items.map((grant) => <li className="factor" key={grant.id}>
        <div><strong className="mono">{grant.capability}</strong><span className="factor__meta mono">{grant.principal_id} · {grantScopeLabel(grant, { org: (id) => id, project: (id) => id, environment: (id) => id })}</span></div>
        <span className="origin-chips">{grant.origins.map((origin) => <span className="badge" key={`${origin.kind}:${origin.subject}`}>{origin.kind}: {origin.subject}</span>)}</span>
        <button type="button" className="btn" disabled={revokeGrant.isPending} onClick={() => revoke(grant)}>Revoke</button>
      </li>) : null}</ul>
      <h3>New instance grant</h3>
      <div className="field"><label htmlFor={principalId}>Principal ID</label><input id={principalId} className="mono" value={grantPrincipal} onChange={(event) => setGrantPrincipal(event.target.value)} /></div>
      <div className="field"><label htmlFor={`${principalId}-template`}>Role-template shortcut</label><select id={`${principalId}-template`} value={grantTemplate} onChange={(event) => setGrantTemplate(event.target.value)}>
        <option value="">Choose capabilities individually</option>{instanceTemplates.map((template) => <option value={template.id} key={template.id}>{template.id}</option>)}
      </select></div>
      {grantTemplate === '' ? <fieldset className="capability-list"><legend>Instance-admissible capabilities</legend>{instanceCapabilities.map((capability) => <label className="chk" key={capability.id}>
        <input type="checkbox" checked={selectedCapabilities.includes(capability.id)} onChange={(event) => setSelectedCapabilities(event.target.checked ? [...selectedCapabilities, capability.id] : selectedCapabilities.filter((id) => id !== capability.id))} />
        <span><strong className="mono">{capability.id}</strong> — {capability.covers}</span>
      </label>)}</fieldset> : null}
      <div className="panel__actions"><button type="button" className="btn btn--primary" disabled={createGrants.isPending || applyTemplate.isPending || grantPrincipal.trim() === '' || (grantTemplate === '' && selectedCapabilities.length === 0)} onClick={() => {
        const principal = grantPrincipal.trim();
        if (grantTemplate !== '') {
          applyTemplate.mutate({ scope: { kind: 'instance' }, principal, template: grantTemplate }, {
            onSuccess: (result) => { setGrantTemplate(''); ok(`Result for ${String(result.count)} instance grant line${result.count === 1 ? '' : 's'} for ${principal}: ${grantOutcomeSummary(result.items)}`); },
            onError: (error) => report(new SurfaceMessage(grantFailureText(error))),
          });
          return;
        }
        createGrants.mutate({ scope: { kind: 'instance' }, principal, capabilities: selectedCapabilities }, {
          onSuccess: (result) => { setSelectedCapabilities([]); ok(`Result for ${String(result.length)} instance grant line${result.length === 1 ? '' : 's'} for ${principal}: ${grantOutcomeSummary(result)}`); },
          onError: (error) => {
            report(new SurfaceMessage(grantFailureText(error)));
          },
        });
      }}>Create instance grant</button></div>
    </Panel>

    <CredentialPolicyPanel query={policy} onDone={ok} onFailure={report} />

    <Panel id="instance-retention" title="Retention health">
      {health.isPending ? <p role="status">Loading retention health…</p> : null}
      {secondFactor(health.error) ? <Alert>Retention health requires a second factor for this session.</Alert> : null}
      {nondisclosed(health.error) ? <p role="status">Retention health is not disclosed to this session.</p> : null}
      {health.isError && !secondFactor(health.error) && !nondisclosed(health.error) ? <Alert>{settingsFailureText(health.error, 'get-retention-health')}</Alert> : null}
      {health.isSuccess ? <><p role="status">{stale?.kind === 'stale'
        ? health.data.last_prune_success === null ? 'Payload pruning has never succeeded — retention bounds are not being enforced.' : `Payload pruning has not succeeded since ${new Date(health.data.last_prune_success).toLocaleString()} — retention bounds are not being enforced.`
        : `Payload pruning last succeeded ${health.data.last_prune_success === null ? 'never' : new Date(health.data.last_prune_success).toLocaleString()}.`}</p>
        <p className="field__hint">A run is stale after {health.data.stale_after_seconds / 3600} hours. The same fact is a Prometheus gauge and a <span className="mono">hikyo doctor</span> row.</p></> : null}
    </Panel>

    <Panel id="instance-keys" title="Keys &amp; crypto">
      <p><strong>Change-token key.</strong> Rotating it invalidates every client cursor: the next fetch from every workload is a full fetch. There is no restart wave or downtime.</p>
      <div className="panel__actions"><button type="button" className="btn" onClick={() => setConfirmRotate(true)}>Rotate the change-token key</button></div>
      <p className="field__hint">Root-key rotation, master-key rotation, re-encryption, <span className="mono">init</span>, <span className="mono">migrate</span>, restore reconciliation and break-glass are local host authority. They are deliberately absent from every network surface — CLI-at-the-box, not CLI-over-network.</p>
    </Panel>
    {confirmRotate ? <RotateDialog busy={rotate.isPending} failure={rotationFeedback.failure} onCancel={() => { rotationFeedback.clear(); setConfirmRotate(false); }} onConfirm={() => {
      rotationFeedback.clear();
      rotate.mutate(undefined, { onSuccess: () => { ok('The change-token key was rotated. Every client cursor is invalid; the next fetch from each workload is a full one.'); setConfirmRotate(false); }, onError: rotationFeedback.report });
    }} /> : null}
  </div>;
}

function CredentialPolicyPanel({ query, onDone, onFailure }: { query: ReturnType<typeof useCredentialPolicy>; onDone: (message: string) => void; onFailure: (error: unknown) => void }) {
  const update = useSetCredentialPolicy();
  const finiteId = useId(); const liveId = useId(); const indefiniteId = useId();
  const [finite, setFinite] = useState(''); const [live, setLive] = useState(''); const [indefinite, setIndefinite] = useState(false);
  type PolicyProposal = { readonly maxFiniteLifetimeSeconds: number; readonly allowIndefinite: boolean; readonly maxLiveCredentials: number };
  type PolicyPreview = { readonly result: Awaited<ReturnType<typeof update.mutateAsync>>; readonly proposal: PolicyProposal };
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  useEffect(() => { if (query.data !== undefined) { setFinite(String(query.data.max_finite_lifetime_seconds)); setLive(String(query.data.max_live_credentials)); setIndefinite(query.data.allow_indefinite); } }, [query.data]);
  const submit = (confirm: boolean, confirmedProposal?: PolicyProposal) => {
    const proposal = confirmedProposal ?? { maxFiniteLifetimeSeconds: Number(finite), allowIndefinite: indefinite, maxLiveCredentials: Number(live) };
    if (!Number.isInteger(proposal.maxFiniteLifetimeSeconds) || proposal.maxFiniteLifetimeSeconds < 1 || !Number.isInteger(proposal.maxLiveCredentials) || proposal.maxLiveCredentials < 1) return onFailure(new SurfaceMessage('Credential policy values must be whole numbers of at least one.'));
    update.mutate({ ...proposal, confirm }, { onSuccess: (result) => {
      if (!result.applied) return setPreview({ result, proposal });
      setPreview(null);
      void query.refetch();
      onDone(`Credential policy updated. ${String(result.clamped_count)} live credential${result.clamped_count === 1 ? ' was' : 's were'} clamped.`);
    }, onError: onFailure });
  };
  return <Panel id="instance-settings" title="Instance settings">
    <h3>Machine-credential policy</h3>
    {query.isPending ? <p role="status">Loading credential policy…</p> : null}
    {secondFactor(query.error) ? <Alert>Credential policy requires a second factor.</Alert> : null}
    {nondisclosed(query.error) ? <p role="status">Credential policy is not disclosed to this session.</p> : null}
    {query.isError && !secondFactor(query.error) && !nondisclosed(query.error) ? <Alert>{settingsFailureText(query.error, 'get-credential-policy')}</Alert> : null}
    {query.isSuccess ? <>
      <div className="field"><label htmlFor={finiteId}>Maximum finite lifetime (seconds)</label><input id={finiteId} inputMode="numeric" value={finite} onChange={(event) => { setPreview(null); setFinite(event.target.value); }} /></div>
      <div className="field"><label htmlFor={liveId}>Maximum live credentials per service account</label><input id={liveId} inputMode="numeric" value={live} onChange={(event) => { setPreview(null); setLive(event.target.value); }} /></div>
      <div className="field chk"><input id={indefiniteId} type="checkbox" checked={indefinite} onChange={(event) => { setPreview(null); setIndefinite(event.target.checked); }} /><label htmlFor={indefiniteId}>Allow credentials with no expiry</label></div>
      {preview === null ? null : <div className="policy-impact" role="alert"><p>This tightening affects {preview.result.affected.length} live credential{preview.result.affected.length === 1 ? '' : 's'}. Nothing has changed yet.</p><ul>{preview.result.affected.map((credential) => <li key={credential.id} className="mono">{credential.id} — {credential.reason}</li>)}</ul><button type="button" className="btn btn--danger" disabled={update.isPending} onClick={() => submit(true, preview.proposal)}>Apply and affect these credentials</button></div>}
      <div className="panel__actions"><button type="button" className="btn btn--primary" disabled={update.isPending} onClick={() => submit(false)}>Save credential policy</button></div>
    </> : null}
  </Panel>;
}

function RotateDialog({ busy, failure, onCancel, onConfirm }: { busy: boolean; failure: string | null; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useModalDialog();
  return <dialog className="ceremony" ref={dialog} aria-labelledby="rotate-title" onCancel={(event) => { event.preventDefault(); if (!busy) onCancel(); }}>
    <h2 id="rotate-title">Rotate the change-token key?</h2>
    <p className="ceremony__lede">Every conditional-fetch cursor in circulation stops matching. The next fetch from every workload is a full one, and nothing restarts. This cannot be undone by rotating back.</p>
    {busy ? <p role="status">Rotating the key…</p> : null}{failure === null ? null : <Alert>{failure}</Alert>}
    <div className="ceremony__actions"><button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancel</button><button type="button" className="btn btn--danger" onClick={onConfirm} disabled={busy}>Rotate the key</button></div>
  </dialog>;
}
