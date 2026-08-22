import {
  copyValuesOp,
  getRevealWindowOp,
  listEnvironmentsOp,
  listValuesOp,
  reauthPasskeyFinishOp,
  reauthPasskeyStartOp,
  reauthTotpOp,
  revealValueOp,
  revealValuesOp,
  setValueOp,
} from '@hikyo/operations';
import {
  zEnvironmentList,
  zRevealWindow,
  zValueCell,
  zValueList,
} from '@hikyo/zod';
import type { Client } from '@hikyo/runtime-core';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ApiError, parsed } from './client.ts';
import {
  invalidateAfterCopy,
  valuesKey,
  windowKey,
  type EnvRef,
} from './keys.ts';
import { useTransport } from './transport.tsx';

export { valuesKey, windowKey, type EnvRef } from './keys.ts';

/**
 * The value surface and the reveal ceremony, as the SPA sees them (#58).
 *
 * Every response crosses its generated schema before a component sees it, and
 * the WebAuthn legs are no exception: the options blob and the reauth result
 * are contract-bearing even though the browser treats the middle of the
 * ceremony as opaque bytes.
 *
 * One rule is carried here rather than in the components, because it is the
 * one that is easy to get subtly wrong: **the window gates the prompt, never
 * the check**. So a refusal from a disclosure route is NOT read as "the window
 * lapsed, prompt again". A 403 there means the server refused the disclosure —
 * most often a grant revoked under an open window — and the honest response is
 * to remask and say so, not to loop the human through a ceremony that will
 * refuse again.
 */

export type ValueCell = z.infer<typeof zValueCell>;
export type ValueList = z.infer<typeof zValueList>;
export type RevealWindow = z.infer<typeof zRevealWindow>;

export type EnvironmentList = z.infer<typeof zEnvironmentList>;

/** useEnvironments lists the project's environments — the copy destinations. */
export function useEnvironments(env: EnvRef): UseQueryResult<EnvironmentList> {
  const transport = useTransport();
  return useQuery({
    queryKey: ['environments', env.org, env.project] as const,
    queryFn: () =>
      parsed(listEnvironmentsOp, { path: { org: env.org, project: env.project }, ...transport }),
    retry: false,
  });
}

/** useValues is the masked read: write-presence for secrets, plaintext for config. */
export function useValues(env: EnvRef): UseQueryResult<ValueList> {
  const transport = useTransport();
  return useQuery({
    queryKey: valuesKey(env),
    queryFn: () =>
      parsed(listValuesOp, {
          path: {
            org: env.org,
            project: env.project,
            environment: env.environment,
          },
          ...transport,
        }),
    retry: false,
  });
}

/**
 * fetchRevealWindow reads the guard's state for ONE environment on demand.
 *
 * The hook below covers the environment the surface is standing in; this
 * covers the one an act is aimed AT — a copy destination, which has its own
 * protected flag and therefore its own answer. Reusing the source's state
 * there would let a live window in development stand in for authority over
 * production, which is exactly what the protected cap exists to refuse.
 */
export async function fetchRevealWindow(
  env: EnvRef,
  // Imperative, so it cannot read the transport from context like a hook: the
  // caller (a hook that CAN) passes it. Undefined means this instance's own
  // server; a workspace client means the remote's window, over the bearer.
  client?: Client,
): Promise<RevealWindow> {
  return parsed(getRevealWindowOp, {
      path: { org: env.org, project: env.project, environment: env.environment },
      client,
    });
}

/**
 * useRevealWindow is what the ceremony modal reads BEFORE prompting.
 *
 * It is refetched rather than derived from the last reauth result, because the
 * server owns the policy: an environment marked protected while the tab was
 * open caps the window at 0, and a client extrapolating from its own last
 * ceremony would keep offering TOTP that the server will refuse.
 */
export function useRevealWindow(env: EnvRef): UseQueryResult<RevealWindow> {
  const transport = useTransport();
  return useQuery({
    queryKey: windowKey(env),
    queryFn: () =>
      parsed(getRevealWindowOp, {
          path: {
            org: env.org,
            project: env.project,
            environment: env.environment,
          },
          ...transport,
        }),
    retry: false,
  });
}

/**
 * base64url helpers. WebAuthn's JSON shapes carry binary as base64url and the
 * browser's credential API wants ArrayBuffers, so exactly one place converts —
 * exported so the account-security enrolment ceremonies (#60) share it rather
 * than growing a second, subtly different copy.
 */
export function fromBase64URL(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  // An ArrayBuffer, not a Uint8Array view: `BufferSource` wants a view over a
  // plain ArrayBuffer and a bare `Uint8Array` is typed over `ArrayBufferLike`,
  // which admits SharedArrayBuffer. Handing back the buffer keeps the browser
  // API's own type honest without a cast.
  const buffer = new ArrayBuffer(binary.length);
  const out = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return buffer;
}

export function toBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export type PasskeyCeremonyInput = {
  /**
   * The decision this ceremony authorizes. It goes into the SIGNED binding, so
   * an assertion given to `reveal` cannot be spent on `publish` over the same
   * environment and keys — the same unit, a different decision.
   *
   * `mint` is the machine-identity row (#61/#67): the credential mint and the
   * grant-widening gate both consume a window opened under this purpose, over
   * each environment the service account reaches in the resulting post-state.
   */
  operation: 'reveal' | 'copy' | 'publish' | 'mint';
  environmentId: string;
  /** The enumerated unit: exactly the keys this one decision covers. */
  keyIds: readonly string[];
};

/**
 * runPasskeyCeremony is the purpose-bound reauth, start to finish.
 *
 * The enumerated unit travels to `start`, which binds the challenge to it, so
 * the assertion the human signs authorizes exactly those keys in exactly that
 * environment. A ceremony that sent no unit would open a window that any
 * disclosure could spend, which is the thing "one decision over exactly the
 * keys below" exists to prevent.
 */
export async function runPasskeyCeremony(input: PasskeyCeremonyInput): Promise<void> {
  const options = await parsed(reauthPasskeyStartOp, {
      body: {
        operation: input.operation,
        environment_id: input.environmentId,
        key_ids: [...input.keyIds],
      },
    });
  const request = requestOptions(options);
  const assertion = await navigator.credentials.get({ publicKey: request });
  if (assertion === null || !(assertion instanceof PublicKeyCredential)) {
    throw new Error('the authenticator returned no assertion');
  }
  const response = assertion.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error('the authenticator returned the wrong response type');
  }
  await parsed(reauthPasskeyFinishOp, {
      body: {
        id: assertion.id,
        rawId: toBase64URL(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: toBase64URL(response.clientDataJSON),
          authenticatorData: toBase64URL(response.authenticatorData),
          signature: toBase64URL(response.signature),
          userHandle: response.userHandle === null ? null : toBase64URL(response.userHandle),
        },
      },
    });
}

/** Run one adapter-purpose passkey ceremony over one zero-window environment. */
export async function runAdapterPasskeyCeremony(input: {
  operation: 'adapter.configure' | 'adapter.credential-set' | 'adapter.adopt' | 'adapter.sync';
  environmentId: string;
  environmentIds: readonly string[];
}): Promise<void> {
  const options = await parsed(reauthPasskeyStartOp, {
      body: {
        operation: 'adapter',
        adapter_operation: input.operation,
        environment_id: input.environmentId,
        environment_ids: [...input.environmentIds],
        key_ids: [],
      },
    });
  const request = requestOptions(options);
  const assertion = await navigator.credentials.get({ publicKey: request });
  if (assertion === null || !(assertion instanceof PublicKeyCredential)) {
    throw new Error('the authenticator returned no assertion');
  }
  const response = assertion.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error('the authenticator returned the wrong response type');
  }
  await parsed(reauthPasskeyFinishOp, {
      body: {
        id: assertion.id,
        rawId: toBase64URL(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: toBase64URL(response.clientDataJSON),
          authenticatorData: toBase64URL(response.authenticatorData),
          signature: toBase64URL(response.signature),
          userHandle: response.userHandle === null ? null : toBase64URL(response.userHandle),
        },
      },
    });
}

/** One TOTP proof opens the adapter-bound windows for every nonzero environment. */
export async function runAdapterTOTPCeremony(
  operation: 'adapter.configure' | 'adapter.credential-set' | 'adapter.adopt' | 'adapter.sync',
  environmentIds: readonly string[],
  code: string,
): Promise<void> {
  await parsed(reauthTotpOp, {
      body: { purpose: 'adapter', operation, environment_ids: [...environmentIds], code },
    });
}

/**
 * requestOptions narrows the server's options blob to what
 * `navigator.credentials.get` needs, validating as it goes.
 *
 * Written by hand rather than through a schema because the values are
 * BUFFERS by the time the browser sees them: a Zod schema would describe the
 * wire shape and then every field would still need converting, so the check
 * and the conversion live together and neither can be skipped.
 */
export function requestOptions(blob: unknown): PublicKeyCredentialRequestOptions {
  if (typeof blob !== 'object' || blob === null) {
    throw new Error('the reauth options were not an object');
  }
  const outer: Record<string, unknown> = { ...blob };
  const inner = outer['publicKey'];
  const source: Record<string, unknown> =
    typeof inner === 'object' && inner !== null ? { ...inner } : outer;

  const challenge = source['challenge'];
  if (typeof challenge !== 'string') {
    throw new Error('the reauth options carried no challenge');
  }
  const request: PublicKeyCredentialRequestOptions = {
    challenge: fromBase64URL(challenge),
  };
  if (typeof source['rpId'] === 'string') {
    request.rpId = source['rpId'];
  }
  if (typeof source['timeout'] === 'number') {
    request.timeout = source['timeout'];
  }
  if (source['userVerification'] === 'required' || source['userVerification'] === 'preferred') {
    request.userVerification = source['userVerification'];
  }
  const allow = source['allowCredentials'];
  if (Array.isArray(allow)) {
    request.allowCredentials = allow.flatMap((entry: unknown) => {
      if (typeof entry !== 'object' || entry === null) {
        return [];
      }
      const record: Record<string, unknown> = { ...entry };
      const id = record['id'];
      if (typeof id !== 'string') {
        return [];
      }
      return [{ id: fromBase64URL(id), type: 'public-key' as const }];
    });
  }
  return request;
}

/** runTOTPCeremony opens a sliding window with a code. */
export async function runTOTPCeremony(environmentId: string, code: string): Promise<void> {
  await parsed(reauthTotpOp, { body: { environment_id: environmentId, code } });
}

/**
 * ceremonyRefusalText names what actually happened.
 *
 * The 409 is the one worth separating: it is the ENVIRONMENT refusing the
 * factor, not the code being wrong, and telling someone their code was wrong
 * when the server never looked at it sends them to re-enrol an authenticator
 * that was fine.
 */
export function ceremonyRefusalText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 409:
        return 'This environment requires a passkey for every disclosure, so a code cannot authorise it.';
      case 401:
        return 'That code did not match. Check your authenticator and try again.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `The reauthentication could not be completed (server error ${error.status}).`;
    }
  }
  if (error instanceof Error && error.name === 'NotAllowedError') {
    return 'The passkey prompt was dismissed or timed out. Nothing was disclosed.';
  }
  return 'The reauthentication could not be completed.';
}

/**
 * disclosureRefusalText is deliberately NOT the same message.
 *
 * A refusal here happened after a ceremony the human already completed, so the
 * useful sentence is about the disclosure, and "your access may have changed"
 * is the honest reading of a 403 on a route whose window was open a moment
 * ago.
 */
export function disclosureRefusalText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 403:
        return 'The server refused this disclosure. Your access may have changed, or the reauthentication no longer covers these keys — nothing was shown.';
      case 404:
        return 'Nothing here to disclose.';
      case 429:
        return 'Too many requests right now. Wait a moment and try again.';
      default:
        return `The values could not be disclosed (server error ${error.status}).`;
    }
  }
  return 'The values could not be disclosed.';
}

/** useRevealOne discloses a single cell. */
export function useRevealOne(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (key: string) =>
      parsed(revealValueOp, {
          path: {
            org: env.org,
            project: env.project,
            environment: env.environment,
            key,
          },
          ...transport,
        }),
    // The window slid (or was spent), so the chip's input has moved.
    onSettled: () => queries.invalidateQueries({ queryKey: windowKey(env) }),
  });
}

/** useRevealAll discloses the whole environment in one decision. */
export function useRevealAll(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: () =>
      parsed(revealValuesOp, {
          path: {
            org: env.org,
            project: env.project,
            environment: env.environment,
          },
          ...transport,
        }),
    onSettled: () => queries.invalidateQueries({ queryKey: windowKey(env) }),
  });
}

/**
 * useSetValue is the write path, including write-only replacement.
 *
 * It STAGES (#51): the edit lands in the caller's own working state and the
 * environment keeps delivering what it delivered, so what comes back is the
 * immutable version id a later publish names — not a cell. The value cache is
 * still invalidated, because the matrix's pending marker moved even though the
 * delivered value did not.
 */
export function useSetValue(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: { key: string; value: string }) =>
      parsed(setValueOp, {
          path: {
            org: env.org,
            project: env.project,
            environment: env.environment,
            key: input.key,
          },
          body: { value: input.value },
          ...transport,
        }),
    onSuccess: () => queries.invalidateQueries({ queryKey: valuesKey(env) }),
  });
}

/** useCopyValues duplicates stored material into other environments. */
export function useCopyValues(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: { keys: readonly string[]; destinations: readonly string[] }) =>
      parsed(copyValuesOp, {
          path: { org: env.org, project: env.project },
          body: {
            source_environment_id: env.environment,
            keys: [...input.keys],
            destination_environment_ids: [...input.destinations],
            confirm_protected: true,
          },
          ...transport,
        }),
    onSuccess: (result, input) =>
      invalidateAfterCopy(queries, env, [
        ...new Set([
          ...input.destinations,
          ...result.copied.map((copied) => copied.destination_environment_id),
        ]),
      ]),
    // Source ceremony state can change even when the mutation refuses.
    onSettled: () => queries.invalidateQueries({ queryKey: windowKey(env) }),
  });
}
