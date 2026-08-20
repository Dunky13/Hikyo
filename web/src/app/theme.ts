/**
 * Theme selection. Dark is the default and is delivered by CSS alone
 * (src/styles/tokens.css), so this module only handles the EXPLICIT choice:
 * absent one, `prefers-color-scheme` decides and nothing here runs.
 *
 * That split is why the CSP can forbid inline script — there is no
 * first-paint theme guard to inline.
 *
 * The choice is ONE piece of state, shared: the header's binary toggle and the
 * account Preferences select both read and write it through the store below, so
 * changing it in one place updates the other in the same document (a bare
 * `storage` event only fires in OTHER tabs). `useThemeChoice` subscribes both to
 * that store; cross-tab writes are mirrored in too.
 */

import { useSyncExternalStore } from 'react';

const STORAGE_KEY = 'hikyo.theme';

export type Theme = 'dark' | 'light';
export type ThemeChoice = Theme | 'system';

function isTheme(value: string | null): value is Theme {
  return value === 'dark' || value === 'light';
}

export function readThemeChoice(): ThemeChoice {
  const stored = globalThis.localStorage?.getItem(STORAGE_KEY) ?? null;
  return isTheme(stored) ? stored : 'system';
}

/** applyTheme writes the DOM attribute and storage. Internal: every caller goes
 *  through setThemeChoice so the in-document subscribers are notified. */
function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === 'system') {
    root.removeAttribute('data-theme');
    globalThis.localStorage?.removeItem(STORAGE_KEY);
    return;
  }
  root.setAttribute('data-theme', choice);
  globalThis.localStorage?.setItem(STORAGE_KEY, choice);
}

/** initTheme applies the stored choice once at startup, before first paint of
 *  any theme-aware control, so a reload lands on the chosen theme without a
 *  mounted toggle having to do it. */
export function initTheme(): void {
  applyTheme(readThemeChoice());
}

const listeners = new Set<() => void>();

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  const onStorage = (event: StorageEvent) => {
    // `null` key is a storage.clear(); either way re-read and mirror it into
    // this document's DOM, then let subscribers re-render.
    if (event.key === STORAGE_KEY || event.key === null) {
      applyTheme(readThemeChoice());
      onChange();
    }
  };
  globalThis.addEventListener?.('storage', onStorage);
  return () => {
    listeners.delete(onChange);
    globalThis.removeEventListener?.('storage', onStorage);
  };
}

/** setThemeChoice is the only writer: it paints the DOM and wakes every
 *  in-document subscriber, so a change in the header shows in Preferences and
 *  the reverse, with no page reload. */
export function setThemeChoice(choice: ThemeChoice): void {
  applyTheme(choice);
  for (const notify of listeners) {
    notify();
  }
}

/** useThemeChoice is the shared hook: the current choice and the one writer. */
export function useThemeChoice(): readonly [ThemeChoice, (choice: ThemeChoice) => void] {
  const choice = useSyncExternalStore(subscribe, readThemeChoice, readThemeChoice);
  return [choice, setThemeChoice];
}

/** prefersDark reports the OS-level preference, defaulting to dark (the app's
 *  own default) where `matchMedia` is unavailable. */
export function prefersDark(): boolean {
  return globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches ?? true;
}

/**
 * effectiveTheme resolves a choice to the theme actually painted: an explicit
 * choice is itself, `system` follows the OS. The header's binary toggle reads
 * this to show the current theme and to flip to its opposite.
 */
export function effectiveTheme(choice: ThemeChoice, systemDark: boolean): Theme {
  if (choice === 'dark' || choice === 'light') {
    return choice;
  }
  return systemDark ? 'dark' : 'light';
}

export function themeLabel(choice: ThemeChoice): string {
  switch (choice) {
    case 'system':
      return 'System theme';
    case 'light':
      return 'Light theme';
    case 'dark':
      return 'Dark theme';
  }
}
