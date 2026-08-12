/// <reference types="vitest/config" />
import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// The build is constrained by the server's CSP baseline, not by taste
// (internal/server/spa.go asserts the header; internal/server/spa_test.go
// asserts it has no `unsafe-inline`). Two settings below exist only to keep
// the emitted document legal under it — they are load-bearing, not tuning.
export default defineConfig({
  // Root-only, per the system-architecture ADR: subpath mounting is deferred,
  // which keeps RP ID/origin and asset resolution trivial.
  base: '/',
  plugins: [react()],
  resolve: {
    alias: {
      // The generated client is consumed as source rather than as a published
      // package: `clients/ts` emits TypeScript and has no build step, and
      // adding one would put a compiled copy of a generated artifact in the
      // tree for no reader. A pnpm workspace was the alternative and was
      // rejected: it relocates the lockfile and breaks the `client` CI job's
      // frozen-lockfile install.
      '@hikyo/client': here('../clients/ts/src/generated/index.ts'),
      '@hikyo/zod': here('../clients/ts/src/generated/zod.gen.ts'),
      '@hikyo/runtime': here('../clients/ts/src/generated/client.gen.ts'),
    },
  },
  build: {
    outDir: here('../internal/webui/dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    // No data: URIs. Inlining would need `img-src data:` in the CSP, which is
    // a relaxation bought for a few hundred bytes.
    assetsInlineLimit: 0,
    modulePreload: {
      // The polyfill is injected as an INLINE script, which the CSP forbids.
      // Every browser this ships to supports modulepreload natively.
      polyfill: false,
    },
  },
  // Unit tests live in the build config so they resolve `@hikyo/*` through the
  // same aliases the bundle does; a second config file would be a second place
  // for that mapping to be wrong.
  test: {
    // Playwright owns `.spec.ts` under e2e/flows. Picking those up here would
    // fail on a missing browser, or — worse — skip and look like coverage.
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'e2e/**/*.test.ts'],
    environment: 'node',
  },
});
