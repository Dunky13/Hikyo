#!/usr/bin/env node

import { access, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, relative, resolve } from 'node:path';

const require = createRequire(new URL('../../docs/site/package.json', import.meta.url));
const { z } = require('zod');

const ledgerSchemaId = 'hikyo.dev/implementation-status/v1';
const idPattern = /^(CAP|OBL)-[A-Z0-9]+(?:-[A-Z0-9]+)*$/;
const sourceIdPattern = /`((?:CAP|OBL)-[A-Z0-9]+(?:-[A-Z0-9]+)*)`/g;
const startMarker = '<!-- implementation-status:start -->';
const endMarker = '<!-- implementation-status:end -->';
const nonEmptyText = z.string().trim().min(1);
const evidenceSchema = z.union([
	z.object({ label: nonEmptyText, path: nonEmptyText }).strict(),
	z.object({ label: nonEmptyText, url: z.url() }).strict(),
]);
const entryBase = {
	id: z.string().regex(idPattern),
	title: nonEmptyText,
	evidence: z.array(evidenceSchema).min(1),
};
const capabilityImplementedSchema = z
	.object({
		...entryBase,
		kind: z.literal('capability'),
		status: z.literal('implemented'),
		implemented: nonEmptyText,
	})
	.strict();
const capabilityPartialSchema = z
	.object({
		...entryBase,
		kind: z.literal('capability'),
		status: z.literal('partial'),
		implemented: nonEmptyText,
		remaining: nonEmptyText,
	})
	.strict();
const capabilityOpenSchema = z
	.object({
		...entryBase,
		kind: z.literal('capability'),
		status: z.literal('open'),
		remaining: nonEmptyText,
	})
	.strict();
const obligationSchema = z
	.object({
		...entryBase,
		kind: z.literal('obligation'),
		status: z.enum(['implemented', 'partial', 'open', 'accepted']),
		summary: nonEmptyText,
		source: nonEmptyText,
		blocks: z.string().regex(/^CAP-[A-Z0-9]+(?:-[A-Z0-9]+)*$/).optional(),
		nonBlocking: nonEmptyText.optional(),
	})
	.strict()
	.superRefine((entry, context) => {
		if (entry.status !== 'open' && entry.status !== 'partial') return;
		if ((entry.blocks === undefined) === (entry.nonBlocking === undefined)) {
			context.addIssue({
				code: 'custom',
				message: 'open/partial obligations require exactly one of blocks or nonBlocking',
			});
		}
	});
const ledgerDocumentSchema = z
	.object({
		schema: z.literal(ledgerSchemaId),
		entries: z
			.array(
				z.union([
					capabilityImplementedSchema,
					capabilityPartialSchema,
					capabilityOpenSchema,
					obligationSchema,
				]),
			)
			.min(1),
	})
	.strict();

const capabilityPresentations = {
	implemented: {
		heading: 'Fully implemented',
		headers: ['Feature', 'Included'],
		cells: (entry) => [entry.implemented],
		summary: (entry) => entry.implemented,
	},
	partial: {
		heading: 'Partially implemented',
		headers: ['Feature', 'What works now', 'Needed for complete implementation'],
		cells: (entry) => [entry.implemented, entry.remaining],
		summary: (entry) => `${entry.implemented} Remaining: ${entry.remaining}`,
	},
	open: {
		heading: 'Not started',
		headers: ['Feature', 'Needed for implementation'],
		cells: (entry) => [entry.remaining],
		summary: (entry) => entry.remaining,
	},
};

function fail(message) {
	throw new Error(`documentation status: ${message}`);
}

function parseArguments(argv) {
	let mode;
	let root = process.cwd();

	for (let index = 0; index < argv.length; index += 1) {
		const argument = argv[index];
		if (argument === '--check' || argument === '--write') {
			if (mode !== undefined) fail('choose exactly one of --check or --write');
			mode = argument.slice(2);
			continue;
		}
		if (argument === '--root') {
			index += 1;
			if (argv[index] === undefined) fail('--root requires a path');
			root = argv[index];
			continue;
		}
		fail(`unknown argument ${argument}`);
	}

	if (mode === undefined) fail('choose exactly one of --check or --write');
	return { mode, root: resolve(root) };
}

async function validateEvidence(root, entry) {
	let localEvidence = 0;
	for (const [index, evidence] of entry.evidence.entries()) {
		if (evidence.url !== undefined) {
			try {
				const url = new URL(evidence.url);
				if (url.protocol !== 'https:') fail(`${entry.id} evidence URL must use HTTPS`);
			} catch (error) {
				if (error.message.startsWith('documentation status:')) throw error;
				fail(`${entry.id}.evidence[${index}].url is invalid`);
			}
			continue;
		}

		if (isAbsolute(evidence.path)) fail(`${entry.id} evidence path must be relative`);
		const target = resolve(root, evidence.path);
		if (relative(root, target).startsWith('..')) {
			fail(`${entry.id} evidence path escapes the repository`);
		}
		try {
			await access(target);
		} catch {
			fail(`${entry.id} evidence path does not exist: ${evidence.path}`);
		}
		localEvidence += 1;
	}

	if (localEvidence === 0) {
		fail(`${entry.id} must link at least one repository evidence file`);
	}
}

async function loadLedger(root) {
	const ledgerPath = resolve(root, 'docs/status/ledger.json');
	let ledger;
	try {
		ledger = ledgerDocumentSchema.parse(JSON.parse(await readFile(ledgerPath, 'utf8')));
	} catch (error) {
		fail(`cannot parse docs/status/ledger.json: ${error.message}`);
	}

	const ids = new Set();
	for (const entry of ledger.entries) {
		if (ids.has(entry.id)) fail(`duplicate stable ID ${entry.id}`);
		ids.add(entry.id);
		const expectedPrefix = entry.kind === 'capability' ? 'CAP-' : 'OBL-';
		if (!entry.id.startsWith(expectedPrefix)) {
			fail(`${entry.id} prefix contradicts kind ${entry.kind}`);
		}
		await validateEvidence(root, entry);
	}

	const entriesById = new Map(ledger.entries.map((entry) => [entry.id, entry]));
	for (const obligation of ledger.entries.filter((entry) => entry.kind === 'obligation')) {
		if (obligation.blocks === undefined) continue;
		const capability = entriesById.get(obligation.blocks);
		if (capability === undefined || capability.kind !== 'capability') {
			fail(`${obligation.id}.blocks references unknown capability ${obligation.blocks}`);
		}
		if (
			capability.status === 'implemented' &&
			(obligation.status === 'open' || obligation.status === 'partial')
		) {
			fail(`${capability.id} is implemented while blocking ${obligation.id} is ${obligation.status}`);
		}
	}
	return ledger.entries;
}

async function validateObligationSources(root, entries) {
	const knownIds = new Set(entries.map((entry) => entry.id));
	const obligationsBySource = new Map();
	for (const entry of entries.filter((candidate) => candidate.kind === 'obligation')) {
		const sourceEntries = obligationsBySource.get(entry.source) ?? [];
		sourceEntries.push(entry);
		obligationsBySource.set(entry.source, sourceEntries);
	}

	for (const [source, sourceEntries] of obligationsBySource) {
		if (isAbsolute(source)) fail(`obligation source must be relative: ${source}`);
		const sourcePath = resolve(root, source);
		if (relative(root, sourcePath).startsWith('..')) {
			fail(`obligation source escapes the repository: ${source}`);
		}
		let content;
		try {
			content = await readFile(sourcePath, 'utf8');
		} catch (error) {
			fail(`cannot read obligation source ${source}: ${error.message}`);
		}
		if (/\*\*Status:\*\*/i.test(content)) {
			fail(`${source} contains mutable implementation status`);
		}

		const counts = new Map();
		for (const match of content.matchAll(sourceIdPattern)) {
			const id = match[1];
			if (!knownIds.has(id)) fail(`${source} references unknown stable ID ${id}`);
			counts.set(id, (counts.get(id) ?? 0) + 1);
		}
		for (const entry of sourceEntries) {
			const count = counts.get(entry.id) ?? 0;
			if (count !== 1) {
				fail(`${entry.id} must appear exactly once in ${source}; found ${count}`);
			}
		}
	}
}

async function validateImmutableDocumentCheckboxes(root) {
	for (const directory of ['docs/adr', 'docs/spec']) {
		const directoryPath = resolve(root, directory);
		const descendants = await readdir(directoryPath, { recursive: true });
		for (const descendant of descendants.filter((path) => path.endsWith('.md'))) {
			const path = `${directory}/${descendant}`;
			const content = await readFile(resolve(root, path), 'utf8');
			if (/^\s*[-*]\s+\[[ xX]\]/m.test(content)) {
				fail(`${path} contains a mutable implementation checkbox`);
			}
		}
	}
}

function evidenceLinks(entry, prefix = '.') {
	return entry.evidence
		.map((evidence) => {
			const target =
				evidence.path === undefined
					? evidence.url
					: prefix === null
						? `https://github.com/Hikyo-Org/Hikyo/blob/main/${evidence.path}`
						: `${prefix}/${evidence.path}`;
			return `[${evidence.label}](${target})`;
		})
		.join(', ');
}

function renderReadme(entries) {
	const capabilities = entries.filter((entry) => entry.kind === 'capability');
	const lines = [
		startMarker,
		'## Implementation status',
		'',
		'<details>',
		'<summary>Show fully implemented, partially implemented, and open features</summary>',
		'',
		'“Implemented” means the feature and its acceptance evidence are present in the',
		'repository. The machine-checked [implementation-status ledger](./docs/status/README.md)',
		'is the only current-status authority; ADRs/specs define obligations and handoffs',
		'remain immutable evidence.',
	];

	for (const [status, presentation] of Object.entries(capabilityPresentations)) {
		const members = capabilities.filter((entry) => entry.status === status);
		if (members.length === 0) continue;
		lines.push(
			'',
			`### ${presentation.heading}`,
			'',
			`| ${presentation.headers.join(' | ')} |`,
		);
		lines.push(`| ${presentation.headers.map(() => '---').join(' | ')} |`);
		for (const entry of members) {
			const feature = `[\`${entry.id}\`](./docs/status/README.md#${entry.id.toLowerCase()}) ${entry.title}`;
			lines.push(`| ${[feature, ...presentation.cells(entry)].join(' | ')} |`);
		}
	}

	lines.push('', '</details>', endMarker);
	return `${lines.join('\n')}\n`;
}

function statusSummary(entry) {
	if (entry.kind === 'obligation') return entry.summary;
	return capabilityPresentations[entry.status].summary(entry);
}

function renderStatusDocument(entries) {
	const lines = [
		'# Hikyo implementation status',
		'',
		'<!-- Generated by scripts/ci/check-doc-status.mjs from ledger.json. Do not edit. -->',
		'',
		'`docs/status/ledger.json` is the sole mutable authority for current implementation',
		'status. Specs and ADRs define obligations. Handoffs are immutable evidence.',
		'',
		'| ID | Kind | Status | Current state | Evidence |',
		'| --- | --- | --- | --- | --- |',
	];
	for (const entry of entries) {
		lines.push(
			`| <a id="${entry.id.toLowerCase()}"></a>\`${entry.id}\` | ${entry.kind} | ${entry.status} | ${statusSummary(entry)} | ${evidenceLinks(entry, null)} |`,
		);
	}
	lines.push('');
	return lines.join('\n');
}

function replaceStatusBlock(readme, generated) {
	const start = readme.indexOf(startMarker);
	const end = readme.indexOf(endMarker);
	if (start === -1 || end === -1 || end < start) {
		fail(`README.md must contain one ${startMarker}/${endMarker} block`);
	}
	if (readme.indexOf(startMarker, start + startMarker.length) !== -1) {
		fail('README.md contains duplicate implementation-status start markers');
	}
	if (readme.indexOf(endMarker, end + endMarker.length) !== -1) {
		fail('README.md contains duplicate implementation-status end markers');
	}
	const suffixStart = end + endMarker.length;
	const suffix = readme.slice(suffixStart).replace(/^\n?/, '\n');
	return `${readme.slice(0, start)}${generated.trimEnd()}${suffix}`;
}

async function main() {
	const { mode, root } = parseArguments(process.argv.slice(2));
	const entries = await loadLedger(root);
	await validateObligationSources(root, entries);
	await validateImmutableDocumentCheckboxes(root);

	const readmePath = resolve(root, 'README.md');
	const statusPath = resolve(root, 'docs/status/README.md');
	const currentReadme = await readFile(readmePath, 'utf8');
	const expectedReadme = replaceStatusBlock(currentReadme, renderReadme(entries));
	const expectedStatus = renderStatusDocument(entries);

	if (mode === 'write') {
		await mkdir(dirname(statusPath), { recursive: true });
		await writeFile(readmePath, expectedReadme);
		await writeFile(statusPath, expectedStatus);
		return;
	}

	if (currentReadme !== expectedReadme) {
		fail('README.md implementation status is stale; run check-doc-status.mjs --write');
	}
	let currentStatus;
	try {
		currentStatus = await readFile(statusPath, 'utf8');
	} catch (error) {
		fail(`cannot read generated docs/status/README.md: ${error.message}`);
	}
	if (currentStatus !== expectedStatus) {
		fail('docs/status/README.md is stale; run check-doc-status.mjs --write');
	}
	process.stdout.write(`documentation status: ${entries.length} ledger entries verified\n`);
}

main().catch((error) => {
	process.stderr.write(`${error.message}\n`);
	process.exitCode = 1;
});
