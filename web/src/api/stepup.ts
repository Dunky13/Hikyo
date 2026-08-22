import {
  passkeyLoginFinishOp,
  passkeyLoginStartOp,
  stepUpPasskeyFinishOp,
  stepUpPasskeyStartOp,
  stepUpTotpOp,
} from '@hikyo/operations';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { ApiError, parsed } from './client.ts';
import type { WhoAmI } from './session.ts';
import { requestOptions, toBase64URL } from './values.ts';

/**
 * Session assurance, as the browser needs it (human-auth ADR § Assurance).
 *
 * A browser session is minted at password assurance and stays there until the
 * human presents a second factor IN THIS SESSION: enrolling an authenticator
 * proves nothing about the session that enrolled it. Every MFA-mandatory
 * surface — instance administration, grants, reveal — is refused until then,
 * so the shell has to offer the step-up where the refusal would otherwise
 * land, rather than telling the human to "sign in again" into a login page
 * that only ever asks for a password.
 */
export function hasSecondFactor(session: WhoAmI): boolean {
  return session.session.assurance.factors.some(
    (factor) => factor === 'totp' || factor === 'webauthn',
  );
}

/** stepUpFailureText names the refusal without inventing a cause. */
export function stepUpFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return 'No authenticator stands on this account, so there is no code to present. Enrol one under Account & security first.';
      case 401:
        return 'That code was not accepted. A code is valid for one time step and is used once: wait for the next code and try again.';
      case 409:
        return error.detail !== undefined && error.detail !== ''
          ? `${error.detail}.`
          : 'That code was already used for its time step: wait for the next code and try again.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `The step-up could not be completed (server error ${error.status}). Try again shortly.`;
    }
  }
  if (error instanceof Error && error.name === 'NotAllowedError') {
    return 'The passkey prompt was dismissed. Nothing changed.';
  }
  return 'The step-up could not be completed: the server could not be reached, or it answered something this client does not understand.';
}

/**
 * useStepUpTotp elevates the acting browser session with an authenticator
 * code. The server rotates the session token onto the cookie; the body is
 * parsed for contract conformance and every cached answer is re-read, because
 * each of them was computed under the assurance that just changed.
 */
export function useStepUpTotp() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async (code: string) => {
      const result = await parsed(stepUpTotpOp, { body: { code } });
      if (result.session.artifact === 'browser' && result.session_token !== undefined) {
        throw new Error('the server returned a browser session token in the response body');
      }
      return result;
    },
    onSuccess: () => queries.invalidateQueries(),
  });
}

/** useStepUpPasskey elevates the acting session with a passkey assertion. */
export function useStepUpPasskey() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const options = await parsed(stepUpPasskeyStartOp, {});
      const body = await assert(options);
      const result = await parsed(stepUpPasskeyFinishOp, { body });
      if (result.session.artifact === 'browser' && result.session_token !== undefined) {
        throw new Error('the server returned a browser session token in the response body');
      }
      return result;
    },
    onSuccess: () => queries.invalidateQueries(),
  });
}

/**
 * usePasskeyLogin is the discoverable-credential sign-in: fully pre-auth, it
 * names no account, and the session it mints already carries webauthn
 * assurance — no step-up follows.
 */
export function usePasskeyLogin() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const options = await parsed(passkeyLoginStartOp, {});
      const body = await assert(options);
      const result = await parsed(passkeyLoginFinishOp, { body });
      if (result.session.artifact === 'browser' && result.session_token !== undefined) {
        throw new Error('the server returned a browser session token in the response body');
      }
      return result;
    },
    onSuccess: () => queries.invalidateQueries(),
  });
}

/** passkeysAvailable is the feature test the passkey buttons render under. */
export function passkeysAvailable(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';
}

async function assert(options: unknown) {
  const assertion = await navigator.credentials.get({ publicKey: requestOptions(options) });
  if (assertion === null || !(assertion instanceof PublicKeyCredential)) {
    throw new Error('the authenticator returned no assertion');
  }
  const response = assertion.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error('the authenticator returned the wrong response type');
  }
  return {
    id: assertion.id,
    rawId: toBase64URL(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: toBase64URL(response.clientDataJSON),
      authenticatorData: toBase64URL(response.authenticatorData),
      signature: toBase64URL(response.signature),
      userHandle: response.userHandle === null ? null : toBase64URL(response.userHandle),
    },
  };
}
