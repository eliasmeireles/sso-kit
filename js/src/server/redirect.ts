import type { SsoErrorCode } from '../shared/types.js';

/** Adds or replaces error on a login-page URL, preserving its other parameters and fragment. */
export function loginErrorRedirect(loginPage: string, code: SsoErrorCode): string {
  const hashIndex = loginPage.indexOf('#');
  const fragment = hashIndex < 0 ? '' : loginPage.slice(hashIndex);
  const target = hashIndex < 0 ? loginPage : loginPage.slice(0, hashIndex);
  const queryIndex = target.indexOf('?');
  const path = queryIndex < 0 ? target : target.slice(0, queryIndex);
  const params = new URLSearchParams(queryIndex < 0 ? '' : target.slice(queryIndex + 1));
  params.set('error', code);
  return `${path}?${params}${fragment}`;
}
