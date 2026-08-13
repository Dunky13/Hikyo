import { type CollectionEntry, getCollection } from 'astro:content';
import { structure, type StructuredData } from 'fumadocs-core/mdx-plugins';
import { loader, type StaticSource } from 'fumadocs-core/source';
import path from 'node:path';
import { fumadocsBase } from './site';

const contentRoot = 'src/content/docs';

export const source = loader({
  source: await createSource(),
  baseUrl: fumadocsBase,
});

function requireFilePath(entry: CollectionEntry<'docs'> | CollectionEntry<'meta'>): string {
  if (entry.filePath === undefined) {
    throw new Error(`documentation entry ${entry.id} has no source file path`);
  }
  return entry.filePath;
}

function requireBody(entry: CollectionEntry<'docs'>): string {
  if (entry.body === undefined) {
    throw new Error(`documentation page ${entry.id} has no Markdown body`);
  }
  return entry.body;
}

async function createSource() {
  const result: StaticSource<{
    metaData: CollectionEntry<'meta'>['data'];
    pageData: CollectionEntry<'docs'>['data'] & {
      _raw: CollectionEntry<'docs'>;
      structuredData: StructuredData;
    };
  }> = { files: [] };

  for (const page of await getCollection('docs')) {
    result.files.push({
      type: 'page',
      path: path.relative(contentRoot, requireFilePath(page)),
      data: {
        ...page.data,
        _raw: page,
        structuredData: structure(requireBody(page)),
      },
    });
  }

  for (const meta of await getCollection('meta')) {
    result.files.push({
      type: 'meta',
      path: path.relative(contentRoot, requireFilePath(meta)),
      data: meta.data,
    });
  }

  return result;
}
