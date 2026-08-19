import { useEffect, useState } from 'react';
import { generatePath, matchPath, NavLink, Outlet, useLocation, useNavigate } from 'react-router';

import { useLogout, useOrgs, type WhoAmI } from '../api/session.ts';
import { retentionBanner, useRetentionHealth } from '../api/retention.ts';
import {
  applyThemeChoice,
  nextThemeChoice,
  readThemeChoice,
  themeLabel,
  type ThemeChoice,
} from '../app/theme.ts';
import { needsOrg, SECTIONS, SURFACES, surfaceById, type Surface } from '../app/navigation.ts';

/**
 * The application chrome skeleton (prototype/app-chrome iteration 15, sidebar
 * treatment e from iteration 18).
 *
 * Skeleton means: the structure and the navigation are real, the content
 * wells are placeholders. The deep surfaces — environment matrix, reveal and
 * editing, version history, machine access — are their own tickets and arrive
 * as routes into the well, not as changes to this file.
 *
 * Three things here are load-bearing rather than decorative and must survive
 * later edits: the org rail owns organisation switching (iteration 4), the
 * account entry sits at the rail's foot, and the whole thing collapses to a
 * single column with a nav disclosure below 800px.
 */
export function Shell({ session }: { session: WhoAmI }) {
  const orgs = useOrgs(true);
  const retentionHealth = useRetentionHealth(true);
  const location = useLocation();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);
  const [chosenOrgId, setChosenOrgId] = useState('');

  // A navigation on a phone must close the sheet it was chosen from.
  useEffect(() => setNavOpen(false), [location.pathname]);

  const items = orgs.data === undefined ? [] : orgs.data.items;
  const here = matchedSurface(location.pathname);
  const routeOrgId = here?.params.org === undefined ? '' : here.params.org;

  // A deep link is a selection too. Persist it only after the organisation
  // listing confirms the id, then unscoped destinations keep the same tenant.
  useEffect(() => {
    if (routeOrgId !== '' && items.some((org) => org.id === routeOrgId)) {
      setChosenOrgId(routeOrgId);
    }
  }, [items, routeOrgId]);

  /**
   * The active organisation is the ROUTE's when the route names one, and the
   * rail's choice otherwise.
   *
   * The route wins for a reason worth keeping: an org-scoped surface is
   * addressed by its path, so a deep link, a reload and a shared URL all land
   * on the same organisation — and a breadcrumb that named the rail's last
   * choice while the page below administered a different organisation would be
   * a lie in the one place a human checks for it.
   */
  const chosenOrg = items.find((org) => org.id === chosenOrgId);
  const fallbackOrg = chosenOrg === undefined ? items[0] : chosenOrg;
  const activeOrgId =
    routeOrgId !== '' ? routeOrgId : fallbackOrg === undefined ? '' : fallbackOrg.id;
  const activeOrgName = items.find((org) => org.id === activeOrgId)?.name ?? activeOrgId;
  const pruneWarning = retentionBanner(retentionHealth.data, retentionHealth.isError);

  /**
   * chooseOrg is what a rail circle does. Setting the state is only half of
   * it: while the current surface is addressed BY organisation, switching has
   * to move the address too, or the rail would mark one organisation while the
   * page kept administering another. A deeper org-scoped route (a project's
   * settings, the matrix) carries parameters the new organisation has no
   * values for, so switching lands on its project list — the surface a human
   * arriving in an organisation actually wants.
   */
  const chooseOrg = (org: string) => {
    setChosenOrgId(org);
    if (here === undefined || !needsOrg(here.surface)) {
      return;
    }
    const extra = Object.keys(here.params).filter((key) => key !== 'org' && key !== '*');
    void navigate(
      extra.length === 0
        ? generatePath(here.surface.path, { ...here.params, org })
        : surfaceById('projects').path,
    );
  };

  return (
    <div className="chrome" data-nav={navOpen ? 'open' : 'closed'}>
      <a className="skip" href="#content">
        Skip to content
      </a>

      <nav className="rail" aria-label="Organisations">
        <button
          type="button"
          className="btn nav-toggle"
          aria-expanded={navOpen}
          aria-controls="sidebar"
          onClick={() => setNavOpen((open) => !open)}
        >
          Menu
        </button>
        <ul className="rail__orgs">
          {items.map((org) => (
            <li key={org.id}>
              <button
                type="button"
                className="avatar"
                aria-current={org.id === activeOrgId}
                aria-label={`Organisation ${org.name}`}
                title={org.name}
                onClick={() => chooseOrg(org.id)}
              >
                {monogram(org.name)}
              </button>
            </li>
          ))}
        </ul>
        <span className="rail__spacer" />
        <AccountEntry session={session} />
      </nav>

      <nav id="sidebar" className="sidebar" aria-label="Sections" data-open={navOpen}>
        {orgs.isSuccess && items.length === 0 ? (
          // The zero-org state (prototype iteration 14). It is a real state,
          // not an error: a principal whose grants name no organisation has
          // nowhere to navigate yet, and saying so is the whole of it. An
          // instance operator is in exactly this state until someone grants
          // them membership — their enumeration surface is elsewhere and
          // behind its own second factor.
          <p className="sidebar__empty" role="status">
            No organisations yet. You will see one here once you are granted
            access to it.
          </p>
        ) : null}
        {orgs.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>Your organisations could not be loaded. Reload to try again.</span>
          </p>
        ) : null}
        {SECTIONS.map((section) => {
          // An org-scoped destination needs an organisation to point at. With
          // none active the entry is absent rather than dead: a link that
          // resolves to `/orgs//members` is a 404 dressed as navigation.
          const entries = section.items.filter((item) => !needsOrg(item) || activeOrgId !== '');
          if (entries.length === 0) {
            return null;
          }
          return (
            <div className="sidebar__section" key={section.title}>
              <h2>{section.title}</h2>
              <ul className="sidebar__items">
                {entries.map((item) => (
                  <li key={item.path}>
                    <NavLink
                      className="sidebar__link"
                      to={needsOrg(item) ? generatePath(item.path, { org: activeOrgId }) : item.path}
                      end={item.path === '/'}
                    >
                      {item.label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>

      <div className="main">
        <header className="header">
          <ol className="header__crumbs" aria-label="Breadcrumb">
            <li>{activeOrgId === '' ? 'No organisation' : activeOrgName}</li>
            <li aria-hidden="true">/</li>
            <li>{here?.surface.label ?? 'Not found'}</li>
          </ol>
          <span className="header__spacer" />
          <ThemeToggle />
        </header>
        {pruneWarning?.kind === 'error' ? (
          <p className="retention-warning" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>Retention health could not be checked. Reload to try again.</span>
          </p>
        ) : null}
        {pruneWarning?.kind === 'stale' ? (
          <p className="retention-warning" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>
              {pruneWarning.lastPruneSuccess === null ? (
                <>Payload pruning has never succeeded — retention bounds are not being enforced.</>
              ) : (
                <>
                  Payload pruning has not succeeded since{' '}
                  <time dateTime={pruneWarning.lastPruneSuccess}>
                    {new Date(pruneWarning.lastPruneSuccess).toLocaleString()}
                  </time>{' '}
                  — retention bounds are not being enforced.
                </>
              )}
            </span>
          </p>
        ) : null}
        <main className="content" id="content" tabIndex={-1}>
          <Outlet context={{ activeOrgId }} />
        </main>
      </div>
    </div>
  );
}

function AccountEntry({ session }: { session: WhoAmI }) {
  const [open, setOpen] = useState(false);
  const logout = useLogout();
  const name = session.principal.display_name ?? session.principal.id;

  return (
    <>
      <button
        type="button"
        className="avatar"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${name}`}
        onClick={() => setOpen((v) => !v)}
      >
        {monogram(name)}
      </button>
      {open ? (
        <div className="menu" role="menu" aria-label="Account">
          <p className="menu__label">
            Signed in as <span className="mono">{name}</span>
          </p>
          <button
            type="button"
            role="menuitem"
            className="menu__item"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
          >
            Sign out
          </button>
        </div>
      ) : null}
    </>
  );
}

function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(() => readThemeChoice());

  useEffect(() => applyThemeChoice(choice), [choice]);

  return (
    <button
      type="button"
      className="btn"
      onClick={() => setChoice(nextThemeChoice(choice))}
      // The label states the CURRENT setting, so the control is readable
      // without seeing the colours it changes — which is the point.
      aria-label={`${themeLabel(choice)}. Change theme.`}
    >
      {themeLabel(choice)}
    </button>
  );
}

/**
 * matchedSurface resolves the current path against the CLOSED surface list —
 * the same table the router is generated from, so the breadcrumb and the
 * organisation the chrome believes it is in can never drift from the route
 * that is actually rendered.
 */
function matchedSurface(
  pathname: string,
): { surface: Surface; params: Record<string, string | undefined> } | undefined {
  for (const surface of SURFACES) {
    const match = matchPath({ path: surface.path, end: true }, pathname);
    if (match !== null) {
      return { surface, params: match.params };
    }
  }
  return undefined;
}

/** monogram is the identity circle's content: one or two letters, never an image. */
function monogram(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return '?';
  }
  if (words.length === 1) {
    const only = words[0];
    if (only === undefined) {
      throw new Error('one-word monogram has no word');
    }
    return only.slice(0, 2).toUpperCase();
  }
  const first = words[0];
  const second = words[1];
  if (first === undefined || second === undefined) {
    throw new Error('multi-word monogram has fewer than two words');
  }
  return (first.charAt(0) + second.charAt(0)).toUpperCase();
}
