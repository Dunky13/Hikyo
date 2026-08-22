import '@fontsource-variable/instrument-sans';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './styles/tokens.css';
import './styles/app.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app/App.tsx';
import { AuthProvider } from './app/AuthProvider.tsx';
import { initTheme } from './app/theme.ts';

// Paint the stored theme choice before first render, so a reload lands on it
// without waiting for a theme-aware control to mount and apply it.
initTheme();

// The fonts are self-hosted npm packages, not a CDN link: `font-src 'self'`
// is part of the CSP baseline, and an external font host would be both a CSP
// relaxation and unsolicited egress the threat model's telemetry stance
// forbids by default.

const host = document.getElementById('root');
if (host === null) {
  // Fail loud: a missing mount point means the document the server served is
  // not the document this bundle was built for.
  throw new Error('hikyo: #root is missing from the document');
}

createRoot(host).render(
  <StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </StrictMode>,
);
