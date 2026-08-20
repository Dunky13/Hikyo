import { useEffect, useState } from 'react';
import { generatePath, matchPath, NavLink, Outlet, useLocation, useNavigate } from 'react-router';

import { useLogout, useOrgs, type WhoAmI } from '../api/session.ts';
import { retentionBanner, useRetentionHealth } from '../api/retention.ts';
import { effectiveTheme, prefersDark, useThemeChoice, type Theme } from '../app/theme.ts';
import { needsOrg, SECTIONS, SURFACES, surfaceById, type Surface } from '../app/navigation.ts';
import { StepUpBanner } from './StepUpBanner.tsx';

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
            No organisations yet. An instance administrator creates one under Instance
            administration (a second factor is required), or with{' '}
            <code>hikyo org create</code>; you will see it here once you are granted access.
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
        <StepUpBanner session={session} />
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

/**
 * The header theme toggle: a binary sun/moon that flips light↔dark. Choosing
 * `system` is left to the account's Preferences panel; the quick control in the
 * chrome is a two-state switch, which is what the polymorphing icon expresses.
 *
 * The icon shows the theme actually painted, so while the choice is `system` it
 * tracks the OS preference live — otherwise a mid-session OS flip would leave a
 * sun over a dark page.
 */
function ThemeToggle() {
  const [choice, setChoice] = useThemeChoice();
  const [systemDark, setSystemDark] = useState(() => prefersDark());

  useEffect(() => {
    const query = globalThis.matchMedia?.('(prefers-color-scheme: dark)');
    if (query === undefined) {
      return;
    }
    const sync = () => setSystemDark(query.matches);
    query.addEventListener('change', sync);
    return () => query.removeEventListener('change', sync);
  }, []);

  const current = effectiveTheme(choice, systemDark);
  const next: Theme = current === 'dark' ? 'light' : 'dark';

  return (
    <button
      type="button"
      className="btn btn--icon"
      onClick={() => setChoice(next)}
      // The label states the ACTION, and the icon the current theme by shape —
      // so the state survives forced-colors, where the fills are repainted.
      aria-label={`Switch to ${next} theme`}
    >
      <ThemeIcon dark={current === 'dark'} />
    </button>
  );
}

/**
 * ThemeIcon is the polymorphing sun↔moon (author: Marc Went). The morph, the
 * ray draw-in and the moon shimmer are CSS in app.css — the CSP forbids inline
 * `<style>`, so nothing renders one here. The sun path is baked as an attribute
 * so a browser without the CSS `d` property still shows a static sun rather
 * than nothing; the CSS overrides it where supported.
 */
function ThemeIcon({ dark }: { dark: boolean }) {
  return (
    <svg
      className={dark ? 'theme-icon theme-icon--dark' : 'theme-icon'}
      viewBox="0 0 100 100"
      width="24"
      height="24"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <path
        className="theme-icon__shine"
        d="M70 49.5C70 60.8218 60.8218 70 49.5 70C38.1782 70 29 60.8218 29 49.5C29 38.1782 38.1782 29 49.5 29C39 45 49.5 59.5 70 49.5Z"
      />
      <g className="theme-icon__rays">
        <path d="M50 2V11" pathLength="1" />
        <path d="M85 15L78 22" pathLength="1" />
        <path d="M98 50H89" pathLength="1" />
        <path d="M85 85L78 78" pathLength="1" />
        <path d="M50 98V89" pathLength="1" />
        <path d="M23 78L16 84" pathLength="1" />
        <path d="M11 50H2" pathLength="1" />
        <path d="M23 23L16 16" pathLength="1" />
      </g>
      <path
        className="theme-icon__shape"
        d="M70 49.5C70 60.8218 60.8218 70 49.5 70C38.1782 70 29 60.8218 29 49.5C29 38.1782 38.1782 29 49.5 29C60 29 69.5 38 70 49.5Z"
      />
    </svg>
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
