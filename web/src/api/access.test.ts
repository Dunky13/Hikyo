import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  blastRadius,
  capabilitiesAt,
  createGrantsSequentially,
  covers,
  defaultScopeValue,
  expandTemplate,
  GrantPartialFailure,
  grantFailureText,
  grantOutcomeSummary,
  grantScopeLabel,
  membershipFailureText,
  membershipRows,
  ROLE_TEMPLATES,
  revokeOutcomeText,
  scopeOf,
  scopeOptions,
  TENANT_CAPABILITIES,
  templatesAt,
  whoCan,
  type ProjectNode,
} from './access.ts';
import { ApiError } from './client.ts';
import type { Grant } from './identities.ts';

const NAMES = {
  org: (id: string) => (id === 'org1' ? 'Ceremonies' : id),
  project: (id: string) => (id === 'p1' ? 'payments' : id),
  environment: (id: string) => (id === 'e-dev' ? 'development' : id === 'e-prod' ? 'production' : id),
};

const TOPOLOGY: readonly ProjectNode[] = [
  {
    id: 'p1',
    name: 'payments',
    environments: [
      { id: 'e-prod', name: 'production', isProtected: true },
      { id: 'e-dev', name: 'development', isProtected: false },
    ],
  },
  {
    id: 'p2',
    name: 'website',
    environments: [{ id: 'e-unknown', name: 'staging', isProtected: null }],
  },
];

function grant(over: Partial<Grant> & { capability: string; scope: Grant['scope'] }): Grant {
  return {
    id: `grn_${over.capability}_${JSON.stringify(over.scope)}`,
    principal_id: 'pri_dana',
    created_at: '2026-08-01T00:00:00Z',
    origins: [{ kind: 'manual', subject: 'pri_admin' }],
    ...over,
  };
}

describe('the closed atom table', () => {
  it('offers every tenant atom at org scope and only environment atoms at environment scope', () => {
    expect(capabilitiesAt('org')).toHaveLength(TENANT_CAPABILITIES.length);
    const atEnv = capabilitiesAt('environment').map((c) => c.id);
    expect(atEnv).toContain('read');
    expect(atEnv).toContain('audit-read');
    // manage-members is project-deepest: an environment-scoped row would be a
    // grant nothing can evaluate, and #55 refuses it by name.
    expect(atEnv).not.toContain('manage-members');
    expect(atEnv).not.toContain('manage-projects');
  });

  it('offers project atoms at project scope but not the org-only ones', () => {
    const atProject = capabilitiesAt('project').map((c) => c.id);
    expect(atProject).toContain('manage-members');
    expect(atProject).toContain('project-settings');
    expect(atProject).not.toContain('manage-projects');
    expect(atProject).not.toContain('credential-reset');
  });

  it('never offers an instance-only atom or the system-created scim one', () => {
    const ids = TENANT_CAPABILITIES.map((c) => c.id);
    for (const instanceOnly of [
      'backup-export',
      'restore',
      'rotate-root-key',
      'rotate-master-key',
      'rotate-dek',
      'reencrypt',
      'instance-config',
      'instance-directory',
      'scim-provision',
    ]) {
      expect(ids).not.toContain(instanceOnly);
    }
  });

  it('gives every atom an explanation, because the (?) toggle has nothing else to show', () => {
    for (const atom of TENANT_CAPABILITIES) {
      expect(atom.covers.length).toBeGreaterThan(10);
    }
  });

  it('offers maintainer and admin only at org and project scope', () => {
    expect(templatesAt('environment').map((t) => t.id)).toEqual([
      'viewer',
      'editor',
      'publisher',
      'revealer',
      'historian',
    ]);
    expect(templatesAt('project').map((t) => t.id)).toHaveLength(ROLE_TEMPLATES.length - 1);
  });

  it('offers every human-grantable atom and only operator at instance scope', () => {
    const atoms = capabilitiesAt('instance').map((atom) => atom.id);
    expect(atoms).toContain('backup-export');
    expect(atoms).toContain('instance-directory');
    expect(atoms).toContain('read');
    expect(atoms).not.toContain('scim-provision');
    expect(templatesAt('instance').map((template) => template.id)).toEqual(['operator']);
  });

  it('expands admin differently at org and project scope', () => {
    expect(expandTemplate('admin', 'org')).toContain('manage-projects');
    expect(expandTemplate('admin', 'project')).not.toContain('manage-projects');
  });
});

describe('scope ordering and the safe default', () => {
  const options = scopeOptions('org1', 'Ceremonies', TOPOLOGY);

  it('orders narrow to wide and puts a protected environment last inside its project', () => {
    expect(options.map((o) => o.label)).toEqual([
      'development',
      'production (protected)',
      'staging (protection unreadable)',
      'payments (every environment)',
      'website (every environment)',
      'Ceremonies (every project and environment)',
    ]);
  });

  it('prefers a confirmed-unprotected staging environment over an earlier development environment', () => {
    const withStaging = scopeOptions('org1', 'Ceremonies', [
      {
        id: 'p1',
        name: 'payments',
        environments: [
          { id: 'e-dev', name: 'development', isProtected: false },
          { id: 'e-stage', name: 'StAgInG', isProtected: false },
          { id: 'e-prod', name: 'production', isProtected: true },
        ],
      },
    ]);
    expect(defaultScopeValue(withStaging)).toBe('env:p1:e-stage');
  });

  it('uses the first confirmed-unprotected environment when staging is absent', () => {
    expect(defaultScopeValue(options)).toBe('env:p1:e-dev');
  });

  it('preselects nothing when no environment is known to be unprotected', () => {
    const risky = scopeOptions('org1', 'Ceremonies', [
      {
        id: 'p1',
        name: 'payments',
        environments: [
          { id: 'e-prod', name: 'production', isProtected: true },
          { id: 'e-x', name: 'staging', isProtected: null },
        ],
      },
    ]);
    // An unreadable flag is not a licence to preselect: "unknown" treated as
    // "fine" is exactly how a production disclosure becomes the default.
    expect(defaultScopeValue(risky)).toBe('');
  });
});

describe('grant refusals', () => {
  it('maps a partial failure with explicit progress and the mapped refusal cause', () => {
    const failure = new GrantPartialFailure(
      [
        { capability: 'read', outcome: 'origin_added' },
        { capability: 'edit', outcome: 'unchanged' },
      ],
      'publish',
      3,
      new ApiError(403, 'forbidden'),
    );

    expect(grantFailureText(failure)).toBe(
      'Completed 2 of 3 (live and listed below). Created: none. Origin added: read. Unchanged: edit. publish was refused: Managing members needs a second factor. Sign in again and present your passkey or a code, then retry.',
    );
  });
});

describe('the org-scope blast radius', () => {
  it('enumerates every project and environment, and says future projects inherit', () => {
    const lines = blastRadius(TOPOLOGY);
    expect(lines).toEqual([
      { project: 'payments', environments: 'production (protected) · development' },
      { project: 'website', environments: 'staging (protection unreadable)' },
      {
        project: 'any project created later',
        environments: 'inherits automatically, with no further decision',
      },
    ]);
  });

  it('says so when a project holds no environments rather than rendering an empty cell', () => {
    expect(blastRadius([{ id: 'p3', name: 'empty', environments: [] }])[0]).toEqual({
      project: 'empty',
      environments: 'no environments yet',
    });
  });
});

describe('membership rows', () => {
  const projectRead = grant({ capability: 'read', scope: { org_id: 'org1', project_id: 'p1' } });
  const projectEdit = grant({ capability: 'edit', scope: { org_id: 'org1', project_id: 'p1' } });
  const environmentReveal = grant({
      capability: 'reveal',
      scope: { org_id: 'org1', project_id: 'p1', environment_id: 'e-dev' },
    });
  const orgManager = grant({ capability: 'manage-members', scope: { org_id: 'org1' } });
  const grants = [projectRead, projectEdit, environmentReveal, orgManager];

  it('groups one row per principal and scope, keeping each capability its own line', () => {
    const rows = membershipRows(grants, NAMES);
    expect(rows).toHaveLength(3);
    const project = rows.find((r) => r.level === 'project');
    expect(project?.scopeLabel).toBe('payments · every environment');
    expect(project?.grants.map((g) => g.capability)).toEqual(['edit', 'read']);
  });

  it('labels each depth by what it reaches, not by its id', () => {
    expect(grantScopeLabel(environmentReveal, NAMES)).toBe('payments · development');
    expect(grantScopeLabel(orgManager, NAMES)).toBe('Ceremonies · every project');
  });

  it('derives every depth from one validated scope helper', () => {
    expect(scopeOf(environmentReveal)).toEqual({
      kind: 'environment',
      org: 'org1',
      project: 'p1',
      environment: 'e-dev',
    });
    expect(scopeOf(grant({ capability: 'read', scope: {} }))).toEqual({ kind: 'instance' });
  });

  it('does not claim revocation removed authority while another origin survives', () => {
    const survivor = {
      ...projectRead,
      origins: [{ kind: 'scim' as const, subject: 'bnd_directory' }],
    };
    const text = revokeOutcomeText(projectRead, survivor, NAMES);
    expect(text).toContain('remains effective');
    expect(text).toContain('scim: bnd_directory');
    expect(text).not.toContain('sessions carrying that authority are gone');
  });
});

describe('who can …?', () => {
  const orgReveal = grant({ capability: 'reveal', scope: { org_id: 'org1' } });
  const devReveal = grant({
      capability: 'reveal',
      scope: { org_id: 'org1', project_id: 'p1', environment_id: 'e-dev' },
    });
  const stagingReveal = grant({
      capability: 'reveal',
      scope: { org_id: 'org1', project_id: 'p2', environment_id: 'e-unknown' },
    });
  const grants = [orgReveal, devReveal, stagingReveal];

  it('counts a grant ABOVE the target, because grants inherit downward', () => {
    const answer = whoCan(grants, 'reveal', {
      kind: 'environment',
      org: 'org1',
      project: 'p1',
      environment: 'e-prod',
    });
    expect(answer).toHaveLength(1);
    expect(answer[0]?.scope.org_id).toBe('org1');
  });

  it('does not count a sibling environment', () => {
    expect(
      covers(stagingReveal, {
        kind: 'environment',
        org: 'org1',
        project: 'p1',
        environment: 'e-dev',
      }),
    ).toBe(false);
  });

  it('does not count a narrower grant as covering the whole org', () => {
    expect(covers(devReveal, { kind: 'org', org: 'org1' })).toBe(false);
  });
});

describe('sequential grant creation', () => {
  it('throws the completed capabilities and exact failed capability when a later create is refused', async () => {
    const refusal = new ApiError(400, 'publish is not admitted');
    const attempted: string[] = [];
    const run = createGrantsSequentially(['read', 'edit', 'publish'], async (capability) => {
      attempted.push(capability);
      if (capability === 'publish') {
        throw refusal;
      }
      if (capability === 'read') {
        return { capability, outcome: 'origin_added' };
      }
      return { capability, outcome: 'unchanged' };
    });

    await expect(run).rejects.toMatchObject({
      completed: [
        { capability: 'read', outcome: 'origin_added' },
        { capability: 'edit', outcome: 'unchanged' },
      ],
      failedCapability: 'publish',
      cause: refusal,
    });
    await expect(run).rejects.toBeInstanceOf(GrantPartialFailure);
    expect(attempted).toEqual(['read', 'edit', 'publish']);
  });

  it('returns each server outcome instead of treating every success as a new grant', async () => {
    const result = await createGrantsSequentially(
      ['read', 'edit', 'publish'],
      async (capability) => {
        switch (capability) {
          case 'read':
            return { capability, outcome: 'created' };
          case 'edit':
            return { capability, outcome: 'origin_added' };
          default:
            return { capability, outcome: 'unchanged' };
        }
      },
    );

    expect(result).toEqual([
      { capability: 'read', outcome: 'created' },
      { capability: 'edit', outcome: 'origin_added' },
      { capability: 'publish', outcome: 'unchanged' },
    ]);
  });
});

describe('grant outcome rendering', () => {
  it('renders all three closed outcomes', () => {
    expect(
      grantOutcomeSummary([
        { capability: 'read', outcome: 'created' },
        { capability: 'edit', outcome: 'origin_added' },
        { capability: 'publish', outcome: 'unchanged' },
      ]),
    ).toBe('Created: read. Origin added: edit. Unchanged: publish.');
  });
});

describe('grant refusals', () => {
  it('reads a 403 as the second-factor refusal it provably is on this surface', () => {
    expect(grantFailureText(new ApiError(403, 'x'))).toContain('second factor');
  });

  it('reads a 409 on revoke as the lockout invariant', () => {
    expect(grantFailureText(new ApiError(409, 'x'))).toContain('manage its members');
  });

  it('does not pretend to know which of the two answers a 404 is', () => {
    expect(grantFailureText(new ApiError(404, 'x'))).toContain('same answer');
  });

  it('never presents a transport failure as a refusal', () => {
    expect(grantFailureText(new TypeError('network'))).toContain('could not be reached');
  });

  it('does not claim an unknown server failure changed nothing', () => {
    expect(grantFailureText(new ApiError(500, 'x'))).toContain('whether the change applied is unknown');
  });

  it('maps membership reads by status without calling every failure MFA', () => {
    expect(membershipFailureText(new ApiError(403, 'x'))).toContain('second factor');
    expect(membershipFailureText(new ApiError(404, 'x'))).toContain('does not exist');
    expect(membershipFailureText(new ApiError(500, 'x'))).toContain('server failed');
    expect(membershipFailureText(new TypeError('network'))).toContain('could not be reached');
  });
});

describe('the domain registry fixture', () => {
  const fixtureSchema = z.object({
    capabilities: z.array(z.object({ id: z.string(), deepest: z.enum(['instance', 'org', 'project', 'environment']) })),
    templates: z.array(z.object({
      id: z.string(),
      levels: z.array(z.enum(['instance', 'org', 'project', 'environment'])),
      seeds_by_level: z.record(z.string(), z.array(z.string())),
    })),
  });
  const fixture = fixtureSchema.parse(
    JSON.parse(readFileSync(new URL('../../../internal/domain/testdata/capabilities.json', import.meta.url), 'utf8')),
  );

  it('pins the TS grantable atoms and per-level template expansion to internal/domain', () => {
    const expectedTenant = fixture.capabilities
      .filter((atom) => atom.deepest !== 'instance' && atom.id !== 'scim-provision')
      .map((atom) => ({ id: atom.id, deepest: atom.deepest }));
    const actualTenant = TENANT_CAPABILITIES
      .map((atom) => ({ id: atom.id, deepest: atom.deepest }))
      .sort((left, right) => left.id.localeCompare(right.id));
    expect(actualTenant).toEqual(expectedTenant);

    const actualTemplates = ROLE_TEMPLATES
      .map((template) => ({
        id: template.id,
        levels: [...template.levels],
        seeds_by_level: Object.fromEntries(
          template.levels.map((level) => [level, [...expandTemplate(template.id, level)]]),
        ),
      }))
      .sort((left, right) => left.id.localeCompare(right.id));
    expect(actualTemplates).toEqual(fixture.templates);

    expect(capabilitiesAt('instance').map((atom) => atom.id).sort()).toEqual(
      fixture.capabilities.filter((atom) => atom.id !== 'scim-provision').map((atom) => atom.id),
    );
  });
});
