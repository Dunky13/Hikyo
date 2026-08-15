import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';

import { useLogout, useOrgs, type WhoAmI } from '../api/session.ts';
import { retentionBanner, useRetentionHealth } from '../api/retention.ts';
import {
  applyThemeChoice,
  nextThemeChoice,
  readThemeChoice,
  themeLabel,
  type ThemeChoice,
} from '../app/theme.ts';
import { SECTIONS } from '../app/navigation.ts';

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
  const [navOpen, setNavOpen] = useState(false);

  // A navigation on a phone must close the sheet it was chosen from.
  useEffect(() => setNavOpen(false), [location.pathname]);

  const items = orgs.data?.items ?? [];
  const activeOrg = items[0];
  const pruneWarning = retentionBanner(retentionHealth.data, retentionHealth.isError);

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
                aria-current={org.id === activeOrg?.id}
                aria-label={`Organisation ${org.name}`}
                title={org.name}
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
          <p className="alert" role="status">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>Your organisations could not be loaded. Reload to try again.</span>
          </p>
        ) : null}
        {SECTIONS.map((section) => (
          <div className="sidebar__section" key={section.title}>
            <h2>{section.title}</h2>
            <ul className="sidebar__items">
              {section.items.map((item) => (
                <li key={item.path}>
                  <NavLink className="sidebar__link" to={item.path} end={item.path === '/'}>
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="main">
        <header className="header">
          <ol className="header__crumbs" aria-label="Breadcrumb">
            <li>{activeOrg?.name ?? 'No organisation'}</li>
            <li aria-hidden="true">/</li>
            <li>{currentLabel(location.pathname)}</li>
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
          <Outlet />
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

function currentLabel(pathname: string): string {
  for (const section of SECTIONS) {
    for (const item of section.items) {
      if (item.path === pathname) {
        return item.label;
      }
    }
  }
  return 'Not found';
}

/** monogram is the identity circle's content: one or two letters, never an image. */
function monogram(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return '?';
  }
  if (words.length === 1) {
    return (words[0] ?? '').slice(0, 2).toUpperCase();
  }
  return ((words[0]?.[0] ?? '') + (words[1]?.[0] ?? '')).toUpperCase();
}
