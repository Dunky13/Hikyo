import { fileURLToPath } from 'node:url';
import { generateSW } from 'workbox-build';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const { count, size, warnings } = await generateSW({
  cleanupOutdatedCaches: true,
  clientsClaim: true,
  globDirectory: dist,
  globIgnores: ['sw.js', 'prototypes/**/*'],
  globPatterns: ['**/*.{css,html,js,json,png,svg,txt,webmanifest,woff,woff2}'],
  ignoreURLParametersMatching: [/^deployment$/, /^utm_/, /^fbclid$/],
  inlineWorkboxRuntime: true,
  skipWaiting: true,
  sourcemap: false,
  swDest: fileURLToPath(new URL('../dist/sw.js', import.meta.url)),
});

if (warnings.length > 0) {
  throw new Error(`PWA build warnings:\n${warnings.join('\n')}`);
}
if (count === 0) {
  throw new Error('PWA build produced an empty precache manifest');
}

console.log(`PWA precached ${count} files (${size} bytes)`);
