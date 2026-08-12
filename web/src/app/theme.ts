/**
 * Theme selection. Dark is the default and is delivered by CSS alone
 * (src/styles/tokens.css), so this module only handles the EXPLICIT choice:
 * absent one, `prefers-color-scheme` decides and nothing here runs.
 *
 * That split is why the CSP can forbid inline script — there is no
 * first-paint theme guard to inline.
 */

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

export function applyThemeChoice(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === 'system') {
    root.removeAttribute('data-theme');
    globalThis.localStorage?.removeItem(STORAGE_KEY);
    return;
  }
  root.setAttribute('data-theme', choice);
  globalThis.localStorage?.setItem(STORAGE_KEY, choice);
}

/** nextThemeChoice cycles system -> light -> dark -> system. */
export function nextThemeChoice(current: ThemeChoice): ThemeChoice {
  switch (current) {
    case 'system':
      return 'light';
    case 'light':
      return 'dark';
    case 'dark':
      return 'system';
  }
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
