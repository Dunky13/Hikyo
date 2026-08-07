import { defineConfig } from '@hey-api/openapi-ts';

// The TypeScript half of the contract chain (system-architecture ADR,
// 2026-08-07 amendment): the SAME 3.1 document that produces the Go strict
// server produces these types and Zod schemas. One contract, all consumers -
// which is what makes `-o json` output, the SPA's parsing and the server's
// validation provably the same shapes rather than three hand-kept copies.
//
// Zod is the runtime half: TypeScript types vanish at build time, so a
// response that violates the contract would otherwise be discovered as an
// undefined property three call frames later. The SPA parses, it does not
// cast.
export default defineConfig({
  input: '../../api/openapi.yaml',
  output: {
    path: 'src/generated',
    // No formatter or linter in the chain: the generated tree is a build
    // artifact whose only reader is the compiler, and running a formatter
    // over it would make the regeneration diff gate report churn that means
    // nothing.
    postProcess: [],
  },
  plugins: [
    '@hey-api/typescript',
    '@hey-api/sdk',
    '@hey-api/client-fetch',
    'zod',
  ],
});
