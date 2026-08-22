import type { BodylessOperation, BodyOperation, Options, TDataShape } from '@hikyo/operations';
import { client } from '@hikyo/runtime';
import { zError } from '@hikyo/zod';
import type { z, ZodObject, ZodRawShape, ZodType } from 'zod';

/**
 * The one place the SPA talks to the server.
 *
 * Three rules live here so no caller has to remember them:
 *
 * 1. **Parse, do not cast.** Every response crosses a generated Zod schema
 *    before any component sees it. TypeScript types vanish at build time; a
 *    server that answers a shape the contract does not describe must fail
 *    HERE, naming the member, not three frames later as `undefined`.
 * 2. **Cookies, always.** The browser session is an HttpOnly `__Host-hikyo`
 *    cookie the SPA can neither read nor set. `credentials: 'same-origin'`
 *    is what makes it travel.
 * 3. **The synchronizer token on every mutation.** It arrives on the
 *    readable `__Host-hikyo-csrf` cookie and is echoed on `X-Hikyo-CSRF`;
 *    without it the server refuses a state-changing cookie request (#56).
 */

const CSRF_COOKIE = '__Host-hikyo-csrf';
const CSRF_HEADER = 'X-Hikyo-CSRF';

/** readCsrfToken returns the synchronizer token, or '' when there is none. */
export function readCsrfToken(cookieString: string = document.cookie): string {
  for (const part of cookieString.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === CSRF_COOKIE) {
      return rest.join('=');
    }
  }
  return '';
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

client.setConfig({
  // Root-only, same-origin: the SPA is served by the instance it talks to, so
  // a base URL would be a second place for the origin to be wrong.
  baseUrl: '',
  credentials: 'same-origin',
});

client.interceptors.request.use((request: Request) => {
  if (SAFE_METHODS.has(request.method.toUpperCase())) {
    return request;
  }
  const token = readCsrfToken();
  if (token !== '') {
    request.headers.set(CSRF_HEADER, token);
  }
  return request;
});

/**
 * ApiError is every refusal the SPA can render. Most callers branch only on
 * `status`. `detail` is present only when the generated error contract parsed
 * an explicitly caller-safe detail from the server; malformed bodies and
 * uniform refusals cannot smuggle arbitrary prose through this boundary.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string | undefined;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function requireResponse(result: { response?: Response | undefined }): Response {
  if (result.response === undefined) {
    throw new Error('SDK call completed without an HTTP response');
  }
  return result.response;
}

/**
 * refusal turns any non-2xx into the ApiError the SPA renders. `detail` survives
 * only when the generated error contract parsed an explicitly caller-safe detail
 * from the body; a malformed or uniform refusal carries none. Both `parsed` and
 * `ok` route their non-2xx here so a bodyless call surfaces the same safe detail
 * a body-bearing one does.
 */
function refusal(response: Response, error: unknown): ApiError {
  const parsed = zError.safeParse(error);
  return new ApiError(
    response.status,
    `request failed with ${response.status}`,
    parsed.success ? parsed.data.error.detail ?? undefined : undefined,
  );
}

/**
 * parsed runs a body-bearing operation and returns its response parsed by the
 * operation's OWN generated schema. The descriptor binds the call and that
 * schema together, so no caller can pair an operation with another's model. A
 * non-2xx becomes an ApiError carrying the status; a 2xx whose body does not
 * satisfy the contract throws from Zod, loudly, because a silently-accepted
 * wrong shape is the bug this whole chain exists to stop.
 */
export async function parsed<TData extends TDataShape, TSchema extends ZodType>(
  operation: BodyOperation<TData, TSchema>,
  options: Options<TData, false>,
): Promise<z.infer<TSchema>> {
  const result = await operation.call(options);
  const response = requireResponse(result);
  if (!response.ok) {
    throw refusal(response, result.error);
  }
  if (!operation.successStatuses.includes(response.status)) {
    throw new Error(
      `expected a body-bearing ${operation.successStatuses.join(' or ')}, got ${response.status}: refuse an unbound success response`,
    );
  }
  return operation.response.parse(result.data);
}

/**
 * parsedPick validates a narrow projection of an operation's OWN object schema.
 * Display-once responses use this when unrelated metadata drift must not hide
 * an irretrievable value. The caller supplies keys, never another schema, so
 * operation-to-parser binding remains closed.
 */
export async function parsedPick<
  TData extends TDataShape,
  TShape extends ZodRawShape,
  TMask extends z.util.Mask<keyof TShape>,
>(
  operation: BodyOperation<TData, ZodObject<TShape>>,
  options: Options<TData, false>,
  mask: TMask & Record<Exclude<keyof TMask, keyof TShape>, never>,
) {
  const result = await operation.call(options);
  const response = requireResponse(result);
  if (!response.ok) {
    throw refusal(response, result.error);
  }
  if (!operation.successStatuses.includes(response.status)) {
    throw new Error(
      `expected a body-bearing ${operation.successStatuses.join(' or ')}, got ${response.status}: refuse an unbound success response`,
    );
  }
  return operation.response.pick(mask).parse(result.data);
}

/**
 * ok runs a bodyless operation - one whose success is a status alone.
 *
 * It is deliberately narrow: anything with a body must go through `parsed` so
 * the contract's schema sees it. A success status other than the descriptor's
 * bodyless one means the contract grew a body this caller is ignoring, which is
 * a bug in the caller and is refused as loudly as a failed request rather than
 * silently discarded.
 */
export async function ok<TData extends TDataShape>(
  operation: BodylessOperation<TData>,
  options: Options<TData, false>,
): Promise<void> {
  const result = await operation.call(options);
  const response = requireResponse(result);
  if (!response.ok) {
    throw refusal(response, result.error);
  }
  if (!operation.successStatuses.includes(response.status)) {
    throw new Error(
      `expected a bodyless ${operation.successStatuses.join(' or ')}, got ${response.status}: parse this response instead of discarding it`,
    );
  }
}
