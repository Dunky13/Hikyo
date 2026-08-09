import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://dunky13.github.io',
  base: '/wenv',
  integrations: [
    starlight({
      title: 'Wenv',
      description: 'Fully open-source secrets and configuration across environments.',
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      components: {
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      defaultLocale: 'root',
      editLink: {
        baseUrl: 'https://github.com/Dunky13/wenv/edit/main/',
      },
      lastUpdated: true,
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/Dunky13/wenv' },
      ],
      sidebar: [
        { label: 'Overview', slug: 'index' },
        {
          label: 'Project policy',
          items: [
            { label: 'Security', slug: 'security' },
            { label: 'Support', slug: 'support' },
            { label: 'Governance', slug: 'governance' },
            { label: 'Trademark', slug: 'trademark' },
            { label: 'Contributing', slug: 'contributing' },
            { label: 'License', slug: 'license' },
          ],
        },
        {
          label: 'Release trust',
          items: [{ label: 'Signing ceremony', slug: 'release/signing' }],
        },
      ],
    }),
  ],
});
