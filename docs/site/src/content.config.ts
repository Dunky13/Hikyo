import { glob } from 'astro/loaders';
import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';

const docs = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/docs' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    editUrl: z.url().optional(),
    icon: z.string().optional(),
  }),
});

const meta = defineCollection({
  loader: glob({ pattern: '**/*.{json,yaml,yml}', base: './src/content/docs' }),
  schema: z.object({
    title: z.string().optional(),
    description: z.string().optional(),
    pages: z.array(z.string()).optional(),
    icon: z.string().optional(),
    root: z.boolean().optional(),
  }),
});

export const collections = {
  docs,
  meta,
};
