import { useSessions, useRevokeSession, type ActiveSession } from '../api/remotes.ts';

/**
 * Settings (registry surface `settings`), whose first real panel is the ACTIVE
 * SESSION LIST — the kill switch (#71 criterion 5).
 *
 * A workspace session appears here as its OWN artifact type carrying the origin
 * it was issued to, which is the whole reason it is an ordinary session row: the
 * question an operator actually asks in an incident is "which foreign shell is
 * holding a session on my account", and it has to be answerable at a glance.
 *
 * Revoking bites mid-flight. The row is re-resolved in its own transaction on
 * the next request, so there is no cached-authorization window to wait out.
 *
 * The rest of the account surface — passkeys, TOTP, recovery codes, linked
 * identities — lands with its own tickets and joins this page as further panels.
 */
export function Sessions() {
  const sessions = useSessions();
  const revoke = useRevokeSession();

  return (
    <section className="card" aria-labelledby="sessions-title">
      <h1 id="sessions-title">Settings</h1>
      <h2>Active sessions</h2>
      <p>
        Every artifact currently holding your account. A <span className="mono">workspace</span>{' '}
        session belongs to another instance&apos;s shell operating this one as you — revoking it
        ends that immediately.
      </p>

      {sessions.isError ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>Your sessions could not be loaded. Reload to try again.</span>
        </p>
      ) : null}

      {sessions.isSuccess && sessions.data.items.length === 0 ? (
        <p role="status">No active sessions.</p>
      ) : null}

      <ul className="sessions">
        {(sessions.data?.items ?? []).map((session) => (
          <li key={session.id} className="session">
            <div className="session__head">
              {/* The artifact type is text in a badge, never a colour: it is
                  the single most load-bearing fact in the row. */}
              <span className="badge" data-artifact={session.artifact}>
                {session.artifact}
              </span>
              <span className="mono session__id">{session.id}</span>
            </div>
            <p className="session__detail">{sessionDetail(session)}</p>
            <button
              className="btn"
              type="button"
              aria-label={`Revoke the ${session.artifact} session ${session.id}`}
              onClick={() => revoke.mutate(session.id)}
              disabled={revoke.isPending}
            >
              Revoke
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * sessionDetail is the row's sentence. The requesting origin is stated first
 * for a workspace session because it is the thing being judged.
 */
function sessionDetail(session: ActiveSession): string {
  const seen = `last seen ${new Date(session.last_seen_at).toLocaleString()}`;
  if (session.requesting_origin !== undefined) {
    return `Issued to ${session.requesting_origin} — ${seen}.`;
  }
  const where = session.source_ip === undefined ? '' : ` from ${session.source_ip}`;
  return `Signed in with ${session.auth_method}${where} — ${seen}.`;
}
