import {
  approveCliReauth,
  showCliReauthTransaction,
  type CliReauthApproved,
  type CliReauthTransaction,
} from '@hikyo/client';
import { zCliReauthApproved, zCliReauthTransaction } from '@hikyo/zod';

import { parsed } from './client.ts';

export async function loadCLIReauthTransaction(state: string): Promise<CliReauthTransaction> {
  return parsed(showCliReauthTransaction({ path: { state } }), zCliReauthTransaction);
}

export async function approveCLIReauth(state: string): Promise<CliReauthApproved> {
  return parsed(approveCliReauth({ body: { state } }), zCliReauthApproved);
}

/** Build the only permitted front-channel return: exact bound URI + code/state. */
export function cliReauthCallbackURL(
  transaction: CliReauthTransaction,
  approved: CliReauthApproved,
): string {
  if (approved.state !== transaction.state || approved.redirect_uri !== transaction.redirect_uri) {
    throw new Error('the approved handoff did not match the loaded transaction');
  }
  const target = new URL(transaction.redirect_uri);
  if (target.search !== '' || target.hash !== '') {
    throw new Error('the bound CLI callback was not structurally empty');
  }
  target.searchParams.set('code', approved.code);
  target.searchParams.set('state', approved.state);
  const names = [...target.searchParams.keys()].sort();
  if (names.length !== 2 || names[0] !== 'code' || names[1] !== 'state') {
    throw new Error('the CLI callback gained an unapproved parameter');
  }
  return target.toString();
}
