import { getDefinitionsSettings, setDefinitionsSettings } from '@hikyo/client';
import { zDefinitionsSettings, zSetDefinitionsSettingsRequest } from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { parsed } from './client.ts';

/**
 * Definitions governance is project policy, not repository integration.
 *
 * Hikyo stores the selected authority mode and optional labels supplied by the
 * last apply. It neither knows nor renders a repository URL, and every body is
 * parsed at this boundary before settings UI can rely on it.
 */

export const GIT_DEFINITIONS_NOTICE =
  'Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.';

export type DefinitionsSettings = z.infer<typeof zDefinitionsSettings>;
export type DefinitionsSource = DefinitionsSettings['definitions_source'];

const definitionsSettingsKey = (org: string, project: string) =>
  ['definitions-settings', org, project];

/** Parse a DOM selector value instead of asserting that it is a contract enum. */
export function parseDefinitionsSource(value: string): DefinitionsSource {
  return zSetDefinitionsSettingsRequest.shape.definitions_source.parse(value);
}

/** Shared query options keep the resource key and parsed response together. */
export function definitionsSettingsQueryOptions(org: string, project: string) {
  return {
    queryKey: definitionsSettingsKey(org, project),
    queryFn: () =>
      parsed(getDefinitionsSettings({ path: { org, project } }), zDefinitionsSettings),
    enabled: org !== '' && project !== '',
    retry: false,
  };
}

export function useDefinitionsSettings(
  org: string,
  project: string,
): UseQueryResult<DefinitionsSettings> {
  return useQuery(definitionsSettingsQueryOptions(org, project));
}

export function useSetDefinitionsSettings(org: string, project: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (definitionsSource: DefinitionsSource) =>
      parsed(
        setDefinitionsSettings({
          path: { org, project },
          body: { definitions_source: definitionsSource },
        }),
        zDefinitionsSettings,
      ),
    onSuccess: () =>
      queries.invalidateQueries({ queryKey: definitionsSettingsKey(org, project) }),
  });
}
