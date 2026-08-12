/**
 * The content wells of the chrome skeleton.
 *
 * Each one is a named landing point with a real heading and a real
 * description of what will live there, so the navigation is testable and the
 * accessibility tree is honest — not a grey rectangle labelled "TODO". The
 * ticket that owns the surface replaces the body and leaves the route alone.
 */
export function Placeholder({ title, children }: { title: string; children: string }) {
  return (
    <section className="card" aria-labelledby="well-title">
      <h1 id="well-title">{title}</h1>
      <p>{children}</p>
    </section>
  );
}

export function Overview() {
  return (
    <Placeholder title="Overview">
      The environment matrix lands here — the signature surface, with its
      virtualised grid and cell-state vocabulary.
    </Placeholder>
  );
}

export function Projects() {
  return (
    <Placeholder title="Projects">
      Projects of the active organisation, with their environments and
      definition source.
    </Placeholder>
  );
}

export function Settings() {
  return (
    <Placeholder title="Settings">
      Account and security: sessions by artifact type, passkeys, TOTP, recovery
      codes and linked identities.
    </Placeholder>
  );
}

export function NotFound() {
  return (
    <Placeholder title="Not found">
      That page does not exist. Use the sections on the left to get back.
    </Placeholder>
  );
}
