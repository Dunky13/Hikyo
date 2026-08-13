import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { ApiError } from '../api/client.ts';
import {
  originOf,
  remoteStateText,
  stalenessText,
  useAddRemote,
  useAddWorkspaceOrigin,
  useRemotes,
  useRemoveRemote,
  useRemoveWorkspaceOrigin,
  useRenameRemote,
  useWorkspaceOrigins,
  type Remote,
} from '../api/remotes.ts';
import {
  forgetWorkspace,
  livenessPollMs,
  openPrepared,
  prepareWorkspace,
  probeWorkspace,
  useWorkspaces,
  WorkspaceError,
  type PreparedWorkspace,
  type WorkspaceBearer,
} from '../api/workspace.ts';

/**
 * The multi-instance surface (registry surface `remotes`).
 *
 * Both directions of the relationship live here, because an instance is both at
 * once and there is no "main" anywhere in this design:
 *
 *   - **Directory** (this instance VIEWING others): one card per entry, with
 *     the state, the last-known org and project names, and the "open workspace"
 *     launcher.
 *   - **Consent** (this instance being VIEWED): the origin allowlist, whose
 *     removal is an atomic kill switch rather than a headers change.
 *
 * The cards refresh on a POLL. That is the ADR's own answer and not a
 * simplification: the live channel is `EventSource`, `EventSource` cannot set
 * an `Authorization` header, and weakening SSE authentication to close the gap
 * is forbidden by name.
 */
export function Remotes() {
  const remotes = useRemotes();

  return (
    <>
      <section className="card" aria-labelledby="remotes-title">
        <h1 id="remotes-title">Remotes</h1>
        <p>
          Other Hikyo instances this one knows about. The directory is fetched by this server under
          a pinned credential; opening a workspace is your browser talking to that instance
          directly, as you.
        </p>

        {remotes.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>
              The remote directory could not be read. You may not hold{' '}
              <span className="mono">instance-directory</span> on this instance.
            </span>
          </p>
        ) : null}

        {remotes.isSuccess && remotes.data.items.length === 0 ? (
          <p role="status">
            No remotes yet. Add one below — you will need its URL, its certificate fingerprint and a
            connection credential minted over there.
          </p>
        ) : null}

        <ul className="remotes">
          {(remotes.data?.items ?? []).map((remote) => (
            <RemoteCard key={remote.id} remote={remote} />
          ))}
        </ul>
      </section>

      <AddRemote />
      <OriginAllowlist />
    </>
  );
}

function RemoteCard({ remote }: { remote: Remote }) {
  const rename = useRenameRemote();
  const remove = useRemoveRemote();
  const workspaces = useWorkspaces();
  const [failure, setFailure] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [ended, setEnded] = useState(false);
  const [prepared, setPrepared] = useState<PreparedWorkspace | null>(null);
  const origin = safeOrigin(remote.url);
  const live = workspaces.find((w) => w.origin === origin);
  const staleness = stalenessText(remote);
  useWorkspaceLiveness(live, () => setEnded(true));

  const fail = (error: unknown) =>
    setFailure(
      error instanceof WorkspaceError
        ? error.message
        : 'The workspace could not be opened. Check that this instance allowlists this origin.',
    );

  // Step one: the live compatibility check and the handoff transaction. No
  // window is touched here.
  const prepare = async () => {
    setFailure(null);
    setEnded(false);
    setOpening(true);
    try {
      setPrepared(await prepareWorkspace(origin));
    } catch (error) {
      fail(error);
    } finally {
      setOpening(false);
    }
  };

  // Step two, and it must stay SYNCHRONOUS up to the `window.open` inside
  // `openPrepared`: a popup opened after an await has lost the user gesture and
  // the browser blocks it.
  const go = (ready: PreparedWorkspace) => {
    setPrepared(null);
    openPrepared(ready).catch(fail);
  };

  return (
    <li className="remote">
      <div className="remote__head">
        <h2 className="remote__name">{remote.name}</h2>
        {/* The state is TEXT first. The badge's colour is decoration on top of
            a sentence that already says everything. */}
        <span className="badge" data-state={remote.state}>
          {remote.state}
        </span>
      </div>
      <p className="mono remote__url">{remote.url}</p>

      <p className={remote.state === 'ok' ? 'remote__state' : 'alert'} role="status">
        {remote.state === 'ok' ? null : (
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
        )}
        <span>{remoteStateText(remote)}</span>
      </p>
      {staleness === null ? null : (
        <p className="remote__stale" role="status">
          {staleness}
        </p>
      )}

      <dl className="remote__facts">
        <dt>Identity</dt>
        <dd className="mono">{remote.identity ?? 'not yet observed'}</dd>
        <dt>Version</dt>
        <dd className="mono">{remote.version ?? 'unknown'}</dd>
        <dt>Organisations</dt>
        <dd>{remote.org_count ?? 0}</dd>
        <dt>Projects</dt>
        <dd>{remote.project_count ?? 0}</dd>
      </dl>

      {remote.orgs === undefined || remote.orgs.length === 0 ? null : (
        <ul className="remote__orgs">
          {remote.orgs.map((org) => (
            <li key={org.name}>
              <span className="mono">{org.name}</span>
              <span className="remote__projects">{org.projects.join(', ') || 'no projects'}</span>
            </li>
          ))}
        </ul>
      )}

      {failure === null ? null : (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      )}

      {ended && live === undefined ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            Workspace session ended — that instance revoked it, withdrew consent for this origin,
            or became unreachable. Reconnect to continue.
          </span>
        </p>
      ) : null}

      <div className="remote__actions">
        {live === undefined && prepared !== null ? (
          <button className="btn btn--primary" type="button" onClick={() => go(prepared)}>
            Continue to {origin} to sign in
          </button>
        ) : null}
        {live === undefined && prepared === null ? (
          <button className="btn btn--primary" type="button" onClick={prepare} disabled={opening}>
            {opening ? 'Contacting…' : 'Open workspace'}
          </button>
        ) : null}
        {live === undefined ? null : (
          <>
            <span className="badge" role="status">
              Workspace open
            </span>
            <button className="btn" type="button" onClick={() => forgetWorkspace(origin)}>
              Close workspace
            </button>
          </>
        )}
        <button
          className="btn"
          type="button"
          onClick={() => {
            const next = globalThis.prompt('New display name', remote.name);
            if (next !== null && next !== '' && next !== remote.name) {
              rename.mutate({ remote: remote.name, name: next });
            }
          }}
        >
          Rename
        </button>
        <button className="btn" type="button" onClick={() => remove.mutate(remote.name)}>
          Remove
        </button>
      </div>
      {remove.isSuccess ? (
        <p role="status">
          Removed here. That does <strong>not</strong> revoke the credential — revoke it on the
          other instance too.
        </p>
      ) : null}
    </li>
  );
}

function AddRemote() {
  const add = useAddRemote();
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [pin, setPin] = useState('');
  const [credential, setCredential] = useState('');

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    add.mutate(
      { name, url, spkiPin: pin, credential },
      {
        onSuccess: () => {
          setName('');
          setUrl('');
          setPin('');
          setCredential('');
        },
      },
    );
  };

  return (
    <section className="card" aria-labelledby="add-remote-title">
      <h2 id="add-remote-title">Add a remote</h2>
      <p>
        The URL must be <span className="mono">https</span> and the fingerprint is checked on every
        connection — it replaces the certificate authority as the trust root, which is what makes a
        self-signed instance on your own network safe to point at.
      </p>
      <form className="form" onSubmit={onSubmit} noValidate>
        {add.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>{addFailureText(add.error)}</span>
          </p>
        ) : null}
        <div className="field">
          <label htmlFor="remote-name">Name</label>
          <input id="remote-name" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="remote-url">URL</label>
          <input
            id="remote-url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://hikyo.example"
            required
          />
        </div>
        <div className="field">
          <label htmlFor="remote-pin">Certificate fingerprint</label>
          <input id="remote-pin" value={pin} onChange={(e) => setPin(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="remote-credential">Connection credential</label>
          <input
            id="remote-credential"
            type="password"
            autoComplete="off"
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
            required
          />
        </div>
        <button className="btn btn--primary" type="submit" disabled={add.isPending}>
          {add.isPending ? 'Verifying…' : 'Add remote'}
        </button>
      </form>
    </section>
  );
}

/**
 * The origin allowlist: what THIS instance consents to be operated from.
 *
 * Removal is presented as what it is. De-allowlisting revokes every workspace
 * session bound to that origin in the same transaction, so the confirmation
 * says "kill" rather than "remove" and the result reports the body count.
 */
function OriginAllowlist() {
  const origins = useWorkspaceOrigins();
  const add = useAddWorkspaceOrigin();
  const remove = useRemoveWorkspaceOrigin();
  const [origin, setOrigin] = useState('');

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    add.mutate(origin, { onSuccess: () => setOrigin('') });
  };

  return (
    <section className="card" aria-labelledby="allowlist-title">
      <h2 id="allowlist-title">Workspace origins</h2>
      <p>
        The sites allowed to operate <strong>this</strong> instance from a browser. Exact origins
        only — no wildcards, no subdomain matching. What you are trusting is the code served at that
        origin.
      </p>

      {origins.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            The allowlist could not be read. It is gated on{' '}
            <span className="mono">instance-config</span>.
          </span>
        </p>
      ) : null}

      {origins.isSuccess && origins.data.items.length === 0 ? (
        <p role="status">No origins allowlisted. No browser can operate this instance remotely.</p>
      ) : null}

      <ul className="origins">
        {(origins.data?.items ?? []).map((entry) => (
          <li key={entry.origin} className="origin">
            <span className="mono">{entry.origin}</span>
            <button
              className="btn"
              type="button"
              aria-label={`Remove ${entry.origin} and kill its workspace sessions`}
              onClick={() => remove.mutate(entry.origin)}
            >
              Remove
            </button>
          </li>
        ))}
      </ul>

      {remove.isSuccess ? (
        <p role="status">
          Removed <span className="mono">{remove.data.origin}</span> and revoked{' '}
          {remove.data.sessions_revoked} workspace session
          {remove.data.sessions_revoked === 1 ? '' : 's'} bound to it.
        </p>
      ) : null}

      <form className="form form--inline" onSubmit={onSubmit} noValidate>
        {add.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>That origin was refused. It must be a bare scheme, host and port.</span>
          </p>
        ) : null}
        <div className="field">
          <label htmlFor="origin">Origin</label>
          <input
            id="origin"
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
            placeholder="https://shell.example"
            required
          />
        </div>
        <button className="btn btn--primary" type="submit" disabled={add.isPending}>
          Allow origin
        </button>
      </form>
    </section>
  );
}

/**
 * useWorkspaceLiveness keeps the card honest about a session it does not own.
 *
 * Both of the remote's kill switches — de-allowlisting this origin and revoking
 * the session in its own active-session list — take effect at the remote's next
 * request. This IS that request, so a workspace killed over there stops
 * claiming to be open over here within one poll rather than at the next thing
 * the human tries to do.
 */
function useWorkspaceLiveness(bearer: WorkspaceBearer | undefined, onEnded: () => void): void {
  useQuery({
    queryKey: ['workspace-liveness', bearer?.origin ?? '', bearer?.session ?? ''],
    queryFn: async () => {
      if (bearer === undefined) {
        return true;
      }
      const alive = await probeWorkspace(bearer);
      if (!alive) {
        onEnded();
      }
      return alive;
    },
    enabled: bearer !== undefined,
    refetchInterval: livenessPollMs,
    staleTime: 0,
    retry: false,
  });
}

/** safeOrigin never throws on a stored URL the browser cannot parse. */
function safeOrigin(url: string): string {
  try {
    return originOf(url);
  } catch {
    return url;
  }
}

function addFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return 'That entry was refused: the URL must be a bare https origin and the fingerprint must be the base64 SHA-256 of the public key.';
      case 409:
        return 'That entry was refused at the verifying fetch — it may point at this instance itself, at an instance already added, or at a key that does not match the fingerprint.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `The remote could not be added (server error ${error.status}).`;
    }
  }
  return 'The remote could not be added: the server could not be reached, or it answered something this client does not understand.';
}
