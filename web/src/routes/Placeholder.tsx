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
      Choose a project to open its environment matrix, values, and access
      surfaces.
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
