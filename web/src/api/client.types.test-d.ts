import { getMeta } from '@hikyo/client';
import { getMetaOp, logoutOp } from '@hikyo/operations';
import { zOrg } from '@hikyo/zod';

import { parsed } from './client.ts';

// Compile-time negative fixture for #213: an operation descriptor is the only
// parser-bearing argument. A caller cannot supply another operation's schema.
// @ts-expect-error zOrg is not GetMetaData request options.
void parsed(getMetaOp, zOrg);

const forged = { call: getMeta, successStatuses: [200], response: zOrg };
// @ts-expect-error only the generated registry can construct a branded descriptor.
void parsed(forged, {});

const spreadForged = { ...getMetaOp, response: zOrg };
// @ts-expect-error object spread cannot copy a descriptor's private brand.
void parsed(spreadForged, {});

// @ts-expect-error bodyless descriptors cannot cross the body-parser seam.
void parsed(logoutOp, {});
