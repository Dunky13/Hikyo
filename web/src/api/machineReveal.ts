import {
  getMachineRevealOp,
  setMachineRevealOp,
} from '@hikyo/operations';
import { zMachineRevealSettings } from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { parsed } from './client.ts';

/**
 * The per-project machine-reveal opt-in (source-of-truth ADR): the one act
 * that admits `reveal` grants onto workload and automation principals. Off by
 * default; while off, every machine fetch in the project is configuration and
 * secret presence only, whatever grant rows exist.
 */
export type MachineRevealSettings = z.infer<typeof zMachineRevealSettings>;

const machineRevealKey = (org: string, project: string) => ['machine-reveal', org, project];

export function machineRevealQueryOptions(org: string, project: string) {
  return {
    queryKey: machineRevealKey(org, project),
    queryFn: () => parsed(getMachineRevealOp, { path: { org, project } }),
    enabled: org !== '' && project !== '',
    retry: false,
  };
}

export function useMachineReveal(
  org: string,
  project: string,
): UseQueryResult<MachineRevealSettings> {
  return useQuery(machineRevealQueryOptions(org, project));
}

export function useSetMachineReveal(org: string, project: string) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) =>
      parsed(setMachineRevealOp, { path: { org, project }, body: { enabled } }),
    onSuccess: () => queries.invalidateQueries({ queryKey: machineRevealKey(org, project) }),
  });
}
