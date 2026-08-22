import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildOperationsModule } from './operationsBuilder.ts';

// The operation registry (#213) is generated from the SAME generated artifacts
// the SPA already trusts - sdk.gen.ts for the call, types.gen.ts for the
// success status and body/bodyless split, zod.gen.ts for the response parser.
// Deriving from hey-api's output (not by re-mangling operationIds ourselves)
// keeps the CLI->Cli name mangling in exactly one place and makes the registry
// a CHECKED one: the compiler rejects it the day a referenced symbol drifts.

const here = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./generated/${name}`, import.meta.url)), 'utf8');

const sources = () => ({
  sdkSource: here('sdk.gen.ts'),
  typesSource: here('types.gen.ts'),
  zodSource: here('zod.gen.ts'),
});

test('generation is deterministic: the same inputs yield byte-identical output', () => {
  const input = sources();
  assert.equal(buildOperationsModule(input), buildOperationsModule(input));
});

test('a body-bearing operation binds its call, success status and response parser', () => {
  const module = buildOperationsModule(sources());
  assert.match(
    module,
    /export const showCliReauthTransactionOp: BodyOperation<ShowCliReauthTransactionData, typeof zShowCliReauthTransactionResponse> = \/\* @__PURE__ \*\/ new GeneratedBodyOperation\(showCliReauthTransaction, \[200\], zShowCliReauthTransactionResponse\);/,
  );
});

test('a bodyless operation binds its call and success status, with no parser', () => {
  const module = buildOperationsModule(sources());
  assert.match(
    module,
    /export const logoutOp: BodylessOperation<LogoutData> = \/\* @__PURE__ \*\/ new GeneratedBodylessOperation\(logout, \[204\]\);/,
  );
});

test('an operation with multiple body-bearing success statuses retains the closed set', () => {
  const module = buildOperationsModule(sources());
  assert.match(
    module,
    /export const updateAdapterTargetOp: BodyOperation<UpdateAdapterTargetData, typeof zUpdateAdapterTargetResponse> = \/\* @__PURE__ \*\/ new GeneratedBodyOperation\(updateAdapterTarget, \[200, 202\], zUpdateAdapterTargetResponse\);/,
  );
});

test('a streaming operation binds its call, handshake status and event parser', () => {
  const module = buildOperationsModule(sources());
  assert.match(
    module,
    /export const watchProjectEventsOp: StreamOperation<typeof watchProjectEvents, typeof zWatchProjectEventsResponse> = \/\* @__PURE__ \*\/ new GeneratedStreamOperation\(watchProjectEvents, \[200\], zWatchProjectEventsResponse\);/,
  );
});

test('an sdk function with no generated response, outside the known SCIM skips, fails loud', () => {
  const input = sources();
  assert.throws(
    () =>
      buildOperationsModule({
        ...input,
        sdkSource: `${input.sdkSource}\nexport const inventedGhostOperation = <ThrowOnError extends boolean = false>(options: unknown) => options;\n`,
      }),
    /inventedGhostOperation/,
  );
});

test('the committed operations.gen.ts is exactly what the generator emits now', () => {
  const committed = here('operations.gen.ts');
  assert.equal(committed, buildOperationsModule(sources()));
});
