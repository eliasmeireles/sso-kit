import { timingSafeEqual } from 'node:crypto';
import { validPending } from '../shared/authorization.js';
import { SsoError, type BrowserPending } from '../shared/types.js';

export function readPending(value: string | undefined, state: string | null, redirectUri: string): BrowserPending {
  const parts = typeof value === 'string' ? value.split('.') : [];
  const [savedState, nonce, codeVerifier] = parts;
  if (parts.length !== 3 || !savedState || !nonce || !codeVerifier) throw new SsoError('expired');
  const pending = { state: savedState, nonce, codeVerifier, redirectUri };
  if (!validPending(pending) || !state) throw new SsoError('expired');
  const actual = Buffer.from(state);
  const expected = Buffer.from(savedState);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new SsoError('expired');
  return pending;
}
