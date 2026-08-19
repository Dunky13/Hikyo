import {
  authMethods,
  enrolPasskeyFinish,
  enrolPasskeyStart,
  enrolTotpConfirm,
  enrolTotpStart,
  listIdentities,
  listPasskeys,
  linkIdentity,
  regenerateRecoveryCodes,
  removePasskey,
  removeTotp,
  samlStart,
  unlinkIdentity,
} from '@hikyo/client';
import {
  zAuthMethods,
  zIdentityList,
  zLoginResult,
  zOidcStartResult,
  zPasskeyList,
  zRecoveryCodesResult,
  zSamlStartResult,
  zTotpEnrolStartResult,
  zWebauthnOptions,
} from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ApiError, parsed } from './client.ts';
import { fromBase64URL, toBase64URL } from './values.ts';

/**
 * Account & security (#60), riding the endpoints #54 shipped.
 *
 * Three properties of THIS surface are not cosmetic:
 *
 *  1. **Every mutation here is an account-security mutation.** Confirming a
 *     TOTP enrolment, removing a factor, removing a passkey, regenerating
 *     recovery codes and unlinking an identity all advance the principal's
 *     session generation: every OTHER session that principal holds dies, and
 *     the acting one is reissued in place. For a browser artifact the reissue
 *     arrives on the `__Host-hikyo` cookie and never in the body (#56), so the
 *     client's whole job afterwards is to discard its cached answers and
 *     re-read `whoami` — which is what `invalidateQueries` does here.
 *  2. **A new credential never authorizes its own enrolment.** The proof each
 *     mutation carries is the PRE-EXISTING one: the password, or a confirmed
 *     TOTP code where one stands. The forms ask for that, and the copy says
 *     why.
 *  3. **Enrolment state is only partly readable.** Passkeys and linked
 *     identities have listings; whether a TOTP factor stands does NOT — there
 *     is no read operation for it anywhere in the contract. The panel
 *     therefore states what it can do rather than claiming a state it cannot
 *     observe, and a second enrolment is refused by the server with a named
 *     400 rather than hidden behind a disabled button that guessed.
 */

type PasskeyList = z.infer<typeof zPasskeyList>;
type IdentityList = z.infer<typeof zIdentityList>;
type AuthMethods = z.infer<typeof zAuthMethods>;

const passkeysKey = ['passkeys'] as const;
const identitiesKey = ['identities'] as const;
const authMethodsKey = ['auth-methods'] as const;

export function usePasskeys(): UseQueryResult<PasskeyList> {
  return useQuery({
    queryKey: passkeysKey,
    queryFn: () => parsed(listPasskeys(), zPasskeyList),
    retry: false,
  });
}

export function useIdentities(): UseQueryResult<IdentityList> {
  return useQuery({
    queryKey: identitiesKey,
    queryFn: () => parsed(listIdentities(), zIdentityList),
    retry: false,
  });
}

/**
 * useAuthMethods is what makes the "link another identity" affordance honest:
 * linking starts an OIDC transaction against a CONFIGURED provider, so where
 * an instance has none the surface says so instead of offering a button that
 * could only ever 400.
 */
export function useAuthMethods(): UseQueryResult<AuthMethods> {
  return useQuery({
    queryKey: authMethodsKey,
    queryFn: () => parsed(authMethods(), zAuthMethods),
    retry: false,
  });
}

/** invalidate everything: a reissued session invalidates every cached answer. */
function useAfterAccountMutation(): () => void {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries();
  };
}

export function useEnrolTotpStart() {
  return useMutation({
    mutationFn: (input: { password: string }) =>
      parsed(enrolTotpStart({ body: { password: input.password } }), zTotpEnrolStartResult),
  });
}

export function useConfirmTotp() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: (input: { code: string }) =>
      parsed(enrolTotpConfirm({ body: { code: input.code } }), zLoginResult),
    onSettled: after,
  });
}

export function useRemoveTotp() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: (input: { password: string }) =>
      parsed(removeTotp({ body: { password: input.password } }), zLoginResult),
    onSettled: after,
  });
}

export function useRemovePasskey() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: (input: { id: string; password: string }) =>
      parsed(
        removePasskey({ path: { id: input.id }, body: { password: input.password } }),
        zLoginResult,
      ),
    onSettled: after,
  });
}

export function useRegenerateRecoveryCodes() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: (input: { proof: string }) =>
      parsed(regenerateRecoveryCodes({ body: { proof: input.proof } }), zRecoveryCodesResult),
    onSettled: after,
  });
}

export function useUnlinkIdentity() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: (input: { id: string; password: string }) =>
      parsed(
        unlinkIdentity({ path: { id: input.id }, body: { proof: input.password } }),
        zLoginResult,
      ),
    onSettled: after,
  });
}

export function useLinkIdentity() {
  return useMutation({
    mutationFn: async (input: { provider: string; kind: 'oidc' | 'saml'; proof: string }) => {
      if (input.kind === 'saml') {
        const result = await parsed(
          samlStart({
            path: { provider: input.provider },
            body: { purpose: 'link', proof: input.proof },
          }),
          zSamlStartResult,
        );
        return result.redirect_url;
      }
      const result = await parsed(
        linkIdentity({ body: { provider: input.provider, proof: input.proof } }),
        zOidcStartResult,
      );
      return result.authorization_url;
    },
  });
}

/**
 * useEnrolPasskey runs the whole registration ceremony: the proof, the
 * browser's `navigator.credentials.create`, and the attestation back.
 *
 * The options blob is opaque by contract — the server generates it and the
 * browser consumes it verbatim — so it is NARROWED here rather than parsed
 * into a type: every field the browser API needs is a buffer by the time it
 * sees it, and a schema would describe the wire shape and then leave every
 * conversion still to do. Same argument, same shape as the reveal ceremony's
 * `requestOptions`.
 */
export function useEnrolPasskey() {
  const after = useAfterAccountMutation();
  return useMutation({
    mutationFn: async (input: { password: string }) => {
      const options = await parsed(
        enrolPasskeyStart({ body: { password: input.password } }),
        zWebauthnOptions,
      );
      const credential = await navigator.credentials.create({
        publicKey: passkeyCreationOptions(options),
      });
      if (credential === null || !(credential instanceof PublicKeyCredential)) {
        throw new Error('the authenticator produced no credential');
      }
      const attestation = credential.response;
      if (!(attestation instanceof AuthenticatorAttestationResponse)) {
        throw new Error('the authenticator produced the wrong response type');
      }
      return parsed(
        enrolPasskeyFinish({
          body: {
            id: credential.id,
            rawId: toBase64URL(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: toBase64URL(attestation.clientDataJSON),
              attestationObject: toBase64URL(attestation.attestationObject),
            },
          },
        }),
        zLoginResult,
      );
    },
    onSettled: after,
  });
}

function record(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`the enrolment options carried no ${what}`);
  }
  return { ...value };
}

function requiredString(value: unknown, what: string): string {
  if (typeof value !== 'string') {
    throw new Error(`the enrolment options carried no ${what}`);
  }
  return value;
}

function optionalNumber(value: unknown, what: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`the enrolment options carried an invalid ${what}`);
  }
  return value;
}

function publicKeyType(value: unknown, what: string): 'public-key' {
  if (value !== 'public-key') {
    throw new Error(`the enrolment options carried an invalid ${what}`);
  }
  return 'public-key';
}

function transport(value: unknown): AuthenticatorTransport {
  if (value === 'ble' || value === 'hybrid' || value === 'internal' || value === 'nfc' || value === 'usb') {
    return value;
  }
  throw new Error('the enrolment options carried an invalid credential transport');
}

function excludedCredentials(value: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error('the enrolment options carried invalid excluded credentials');
  }
  return value.map((entry, index) => {
    const source = record(entry, `excluded credential ${String(index + 1)}`);
    const id = requiredString(source['id'], `excluded credential ${String(index + 1)} id`);
    const transports = source['transports'];
    if (transports !== undefined && !Array.isArray(transports)) {
      throw new Error(`the enrolment options carried invalid excluded credential ${String(index + 1)} transports`);
    }
    return {
      id: fromBase64URL(id),
      type: publicKeyType(source['type'], `excluded credential ${String(index + 1)} type`),
      ...(transports === undefined ? {} : { transports: transports.map(transport) }),
    };
  });
}

function authenticatorSelection(value: unknown): AuthenticatorSelectionCriteria | undefined {
  if (value === undefined) {
    return undefined;
  }
  const source = record(value, 'authenticator selection');
  const attachment = source['authenticatorAttachment'];
  const residentKey = source['residentKey'];
  const requireResidentKey = source['requireResidentKey'];
  const verification = source['userVerification'];
  if (attachment !== undefined && attachment !== 'platform' && attachment !== 'cross-platform') {
    throw new Error('the enrolment options carried an invalid authenticator attachment');
  }
  if (residentKey !== undefined && residentKey !== 'discouraged' && residentKey !== 'preferred' && residentKey !== 'required') {
    throw new Error('the enrolment options carried an invalid resident-key policy');
  }
  if (requireResidentKey !== undefined && typeof requireResidentKey !== 'boolean') {
    throw new Error('the enrolment options carried an invalid resident-key requirement');
  }
  if (verification !== undefined && verification !== 'discouraged' && verification !== 'preferred' && verification !== 'required') {
    throw new Error('the enrolment options carried an invalid user-verification policy');
  }
  return {
    ...(attachment === undefined ? {} : { authenticatorAttachment: attachment }),
    ...(residentKey === undefined ? {} : { residentKey }),
    ...(requireResidentKey === undefined ? {} : { requireResidentKey }),
    ...(verification === undefined ? {} : { userVerification: verification }),
  };
}

function prfValues(value: unknown, what: string): AuthenticationExtensionsPRFValues {
  const source = record(value, what);
  return {
    first: fromBase64URL(requiredString(source['first'], `${what} first value`)),
    ...(source['second'] === undefined
      ? {}
      : { second: fromBase64URL(requiredString(source['second'], `${what} second value`)) }),
  };
}

function extensions(value: unknown): AuthenticationExtensionsClientInputs | undefined {
  if (value === undefined) {
    return undefined;
  }
  const source = record(value, 'extensions');
  const largeBlobSource = source['largeBlob'];
  const largeBlob = largeBlobSource === undefined ? undefined : record(largeBlobSource, 'large-blob extension');
  const prfSource = source['prf'];
  const prf = prfSource === undefined ? undefined : record(prfSource, 'PRF extension');
  const byCredentialSource = prf?.['evalByCredential'];
  let evalByCredential: Record<string, AuthenticationExtensionsPRFValues> | undefined;
  if (byCredentialSource !== undefined) {
    const entries = record(byCredentialSource, 'PRF credential map');
    evalByCredential = {};
    for (const [credential, values] of Object.entries(entries)) {
      evalByCredential[credential] = prfValues(values, `PRF values for ${credential}`);
    }
  }
  const boolean = (member: string): boolean | undefined => {
    const candidate = source[member];
    if (candidate !== undefined && typeof candidate !== 'boolean') {
      throw new Error(`the enrolment options carried an invalid ${member} extension`);
    }
    return candidate;
  };
  const appid = source['appid'];
  if (appid !== undefined && typeof appid !== 'string') {
    throw new Error('the enrolment options carried an invalid appid extension');
  }
  const largeBlobRead = largeBlob?.['read'];
  const largeBlobSupport = largeBlob?.['support'];
  if (largeBlobRead !== undefined && typeof largeBlobRead !== 'boolean') {
    throw new Error('the enrolment options carried an invalid large-blob read value');
  }
  if (largeBlobSupport !== undefined && typeof largeBlobSupport !== 'string') {
    throw new Error('the enrolment options carried an invalid large-blob support value');
  }
  return {
    ...(appid === undefined ? {} : { appid }),
    ...(boolean('credProps') === undefined ? {} : { credProps: boolean('credProps') }),
    ...(source['credentialProtectionPolicy'] === undefined
      ? {}
      : { credentialProtectionPolicy: requiredString(source['credentialProtectionPolicy'], 'credential-protection policy') }),
    ...(boolean('enforceCredentialProtectionPolicy') === undefined
      ? {}
      : { enforceCredentialProtectionPolicy: boolean('enforceCredentialProtectionPolicy') }),
    ...(boolean('hmacCreateSecret') === undefined ? {} : { hmacCreateSecret: boolean('hmacCreateSecret') }),
    ...(boolean('minPinLength') === undefined ? {} : { minPinLength: boolean('minPinLength') }),
    ...(largeBlob === undefined
      ? {}
      : {
          largeBlob: {
            ...(largeBlobRead === undefined ? {} : { read: largeBlobRead }),
            ...(largeBlobSupport === undefined ? {} : { support: largeBlobSupport }),
            ...(largeBlob['write'] === undefined
              ? {}
              : { write: fromBase64URL(requiredString(largeBlob['write'], 'large-blob write value')) }),
          },
        }),
    ...(prf === undefined
      ? {}
      : {
          prf: {
            ...(prf['eval'] === undefined ? {} : { eval: prfValues(prf['eval'], 'PRF evaluation') }),
            ...(evalByCredential === undefined ? {} : { evalByCredential }),
          },
        }),
  };
}

export function passkeyCreationOptions(blob: unknown): PublicKeyCredentialCreationOptions {
  const outer = record(blob, 'options object');
  const inner = outer['publicKey'];
  const source = typeof inner === 'object' && inner !== null ? record(inner, 'publicKey') : outer;

  const challenge = source['challenge'];
  if (typeof challenge !== 'string') {
    throw new Error('the enrolment options carried no challenge');
  }
  const rp = record(source['rp'], 'relying party');
  const user = record(source['user'], 'user');
  const userId = user['id'];
  const userName = user['name'];
  if (typeof userId !== 'string' || typeof userName !== 'string') {
    throw new Error('the enrolment options carried an incomplete user');
  }
  const displayName = requiredString(user['displayName'], 'user display name');
  const rpName = requiredString(rp['name'], 'relying-party name');
  const rpId = rp['id'];
  if (rpId !== undefined && typeof rpId !== 'string') {
    throw new Error('the enrolment options carried an invalid relying-party id');
  }
  const params = source['pubKeyCredParams'];
  if (!Array.isArray(params) || params.length === 0) {
    throw new Error('the enrolment options carried no public-key parameters');
  }

  const options: PublicKeyCredentialCreationOptions = {
    challenge: fromBase64URL(challenge),
    rp: {
      name: rpName,
      ...(rpId === undefined ? {} : { id: rpId }),
    },
    user: {
      id: fromBase64URL(userId),
      name: userName,
      displayName,
    },
    pubKeyCredParams: params.map((entry, index) => {
      const parameter = record(entry, `public-key parameter ${String(index + 1)}`);
      const alg = parameter['alg'];
      if (typeof alg !== 'number' || !Number.isInteger(alg)) {
        throw new Error(`the enrolment options carried an invalid public-key parameter ${String(index + 1)} algorithm`);
      }
      return { type: publicKeyType(parameter['type'], `public-key parameter ${String(index + 1)} type`), alg };
    }),
  };
  const timeout = optionalNumber(source['timeout'], 'timeout');
  if (timeout !== undefined) {
    options.timeout = timeout;
  }
  const attestation = source['attestation'];
  if (attestation !== undefined && attestation !== 'none' && attestation !== 'direct' && attestation !== 'indirect' && attestation !== 'enterprise') {
    throw new Error('the enrolment options carried an invalid attestation policy');
  }
  if (attestation !== undefined) {
    options.attestation = attestation;
  }
  const selection = authenticatorSelection(source['authenticatorSelection']);
  if (selection !== undefined) {
    options.authenticatorSelection = selection;
  }
  const excluded = excludedCredentials(source['excludeCredentials']);
  if (excluded !== undefined) {
    options.excludeCredentials = excluded;
  }
  const suppliedExtensions = extensions(source['extensions']);
  if (suppliedExtensions !== undefined) {
    options.extensions = suppliedExtensions;
  }
  return options;
}

/**
 * accountFailureText maps a refusal onto something true.
 *
 * 401 is the only credential refusal, and on THIS surface it has a second
 * meaning worth separating from "your session ended": the account-security
 * proof — the password, or a code — was wrong. Both are 401 and the sentence
 * covers both without pretending to know which; nothing here is presented as
 * "wrong password" unless the server actually refused a credential.
 */
export function accountFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return error.detail ?? 'The account change request was invalid or would leave the account in a forbidden state.';
      case 401:
        return 'That did not authorise the change: the password or code was not accepted, or this session has ended.';
      case 403:
        return 'This account change is not permitted for the current session assurance.';
      case 404:
        return 'There is nothing here to change.';
      case 409:
        return 'The requested change conflicts with the account’s current security state. Reload and review it before trying again.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `The account surface answered an error (${error.status}); whether the change applied is unknown — reload to check.`;
    }
  }
  if (error instanceof Error && error.name === 'NotAllowedError') {
    return 'The authenticator ceremony was dismissed or timed out. Nothing was changed.';
  }
  return 'The account surface could not be reached, or it answered something this client does not understand.';
}
