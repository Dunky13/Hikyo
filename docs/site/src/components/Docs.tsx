import type { AstroProviderProps } from 'fumadocs-core/framework/astro';
import type { Root } from 'fumadocs-core/page-tree';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  EditOnGitHub,
  type DocsPageProps,
} from 'fumadocs-ui/layouts/docs/page';
import { RootProvider } from 'fumadocs-ui/provider/astro';
import type { ReactNode } from 'react';
import { repositoryUrl, siteUrl, themeStorageKey } from '../lib/site';
import SearchDialog from './SearchDialog';

interface Props {
  tree: Root;
  children: ReactNode;
  pathname: string;
  params: AstroProviderProps['params'];
  title: string;
  description?: string;
  editUrl?: string;
  page?: DocsPageProps;
}

export function Docs({
  tree,
  children,
  pathname,
  params,
  title,
  description,
  editUrl,
  page,
}: Props) {
  return (
    <RootProvider
      pathname={pathname}
      params={params}
      theme={{
        attribute: 'class',
        defaultTheme: 'dark',
        enableSystem: false,
        storageKey: themeStorageKey,
      }}
      search={{ SearchDialog }}
    >
      <DocsLayout
        tree={tree}
        githubUrl={repositoryUrl}
        nav={{ title: 'hikyo', url: siteUrl() }}
        links={[
          { text: 'Getting started', url: siteUrl('docs/getting-started/') },
          { text: 'Security', url: siteUrl('security/') },
        ]}
      >
        <DocsPage {...page}>
          <DocsTitle>{title}</DocsTitle>
          <DocsDescription>{description}</DocsDescription>
          <DocsBody>{children}</DocsBody>
          {editUrl ? (
            <div className="docs-edit-link">
              <EditOnGitHub href={editUrl}>Edit this page on GitHub</EditOnGitHub>
            </div>
          ) : null}
        </DocsPage>
      </DocsLayout>
    </RootProvider>
  );
}
