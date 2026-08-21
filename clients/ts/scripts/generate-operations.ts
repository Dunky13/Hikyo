// Thin CLI over buildOperationsModule (#213): read the generated artifacts,
// emit the operation registry beside them. Runs in `pnpm run generate` right
// after openapi-ts, so the committed registry and the regeneration diff gate
// cover it exactly like the hey-api output it derives from.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { buildOperationsModule } from '../src/operationsBuilder.ts';

const generated = (name: string): URL =>
  new URL(`../src/generated/${name}`, import.meta.url);

const read = (name: string): string => readFileSync(fileURLToPath(generated(name)), 'utf8');

const module = buildOperationsModule({
  sdkSource: read('sdk.gen.ts'),
  typesSource: read('types.gen.ts'),
  zodSource: read('zod.gen.ts'),
});

writeFileSync(fileURLToPath(generated('operations.gen.ts')), module);
