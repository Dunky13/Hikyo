import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(scriptDirectory, '..');
const repositoryRoot = resolve(siteRoot, '../..');
const docsRoot = resolve(siteRoot, 'src/content/docs');

const pages = [
  { source: 'SECURITY.md', target: 'security.md', title: 'Security policy' },
  { source: 'SUPPORT.md', target: 'support.md', title: 'Support policy' },
  { source: 'GOVERNANCE.md', target: 'governance.md', title: 'Governance' },
  {
    source: 'docs/status/README.md',
    target: 'implementation-status.md',
    title: 'Implementation status',
  },
  { source: 'TRADEMARK.md', target: 'trademark.md', title: 'Trademark policy' },
  { source: 'CONTRIBUTING.md', target: 'contributing.md', title: 'Contributing' },
  {
    source: 'docs/release/signing.md',
    target: 'release/signing.md',
    title: 'Release signing ceremony',
  },
];

const siteLinks = new Map([
  ['./CONTRIBUTING.md', '/contributing/'],
  ['./GOVERNANCE.md', '/governance/'],
  ['./docs/status/README.md', '/implementation-status/'],
  [
    './docs/handoff/github-org-transfer.md',
    'https://github.com/Hikyo-Org/Hikyo/blob/main/docs/handoff/github-org-transfer.md',
  ],
  ['./SECURITY.md', '/security/'],
  ['./SUPPORT.md', '/support/'],
  ['./TRADEMARK.md', '/trademark/'],
]);

for (const page of pages) {
  await rm(resolve(docsRoot, page.target), { force: true });
}
await rm(resolve(docsRoot, 'policies'), { recursive: true, force: true });
await rm(resolve(docsRoot, 'license.md'), { force: true });
await mkdir(resolve(docsRoot, 'release'), { recursive: true });

for (const page of pages) {
  const source = await readFile(resolve(repositoryRoot, page.source), 'utf8');
  let body = source.replace(/^# .+\n+/, '');
  for (const [repositoryLink, siteLink] of siteLinks) {
    body = body.replaceAll(`(${repositoryLink})`, `(${siteLink})`);
  }
  const destination = resolve(docsRoot, page.target);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(
    destination,
    `---\ntitle: ${page.title}\neditUrl: https://github.com/Hikyo-Org/Hikyo/edit/main/${page.source}\n---\n\n${body}`,
  );
}

const license = await readFile(resolve(repositoryRoot, 'LICENSE'), 'utf8');
await writeFile(
  resolve(docsRoot, 'license.md'),
  `---\ntitle: Mozilla Public License 2.0\neditUrl: https://github.com/Hikyo-Org/Hikyo/edit/main/LICENSE\n---\n\n\`\`\`text\n${license}\`\`\`\n`,
);
