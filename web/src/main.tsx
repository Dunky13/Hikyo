import '@fontsource-variable/instrument-sans';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './styles/tokens.css';
import './styles/app.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app/App.tsx';

// The fonts are self-hosted npm packages, not a CDN link: `font-src 'self'`
// is part of the CSP baseline, and an external font host would be both a CSP
// relaxation and unsolicited egress the threat model's telemetry stance
// forbids by default.

const queries = new QueryClient({
  defaultOptions: {
    queries: {
      // Authorization is evaluated per request at the server's chokepoint and
      // is never cached there. A long client cache would not be an
      // authorization cache — the server still decides — but it would show a
      // revoked reader stale data, so the window stays short.
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
});

const host = document.getElementById('root');
if (host === null) {
  // Fail loud: a missing mount point means the document the server served is
  // not the document this bundle was built for.
  throw new Error('hikyo: #root is missing from the document');
}

createRoot(host).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
