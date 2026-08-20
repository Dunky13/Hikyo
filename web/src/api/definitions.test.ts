import { describe, expect, it } from 'vitest';

import {
  definitionsSettingsQueryOptions,
  GIT_DEFINITIONS_NOTICE,
  parseDefinitionsSource,
} from './definitions.ts';

describe('definitions settings', () => {
  it('enables the project-scoped read only with both identifiers', () => {
    expect(definitionsSettingsQueryOptions('org_1', 'project_1')).toMatchObject({
      queryKey: ['definitions-settings', 'org_1', 'project_1'],
      enabled: true,
      retry: false,
    });
    expect(definitionsSettingsQueryOptions('org_1', '').enabled).toBe(false);
  });

  it('parses selector values through the generated request schema', () => {
    expect(parseDefinitionsSource('db')).toBe('db');
    expect(parseDefinitionsSource('git')).toBe('git');
    expect(() => parseDefinitionsSource('repository')).toThrow();
  });

  it('pins the persistent Git-mode explanation byte for byte', () => {
    expect(GIT_DEFINITIONS_NOTICE).toBe(
      'Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.',
    );
  });
});
