import { createFromSource } from 'fumadocs-core/search/server';
import type { APIRoute } from 'astro';
import { source } from '../../lib/source';

export const prerender = true;

const { staticGET } = createFromSource(source);

export const GET: APIRoute = () => staticGET();
