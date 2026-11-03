import * as oauth from 'oauth4webapi';
import { providerUrl } from './discovery.js';
import { SsoError, type BrowserPending, type LoginConfig } from './types.js';

const opaqueValue = /^[A-Za-z0-9_-]+$/;
const verifierValue = /^[A-Za-z0-9_~-]{43,128}$/;

export async function startAuthorization(config: LoginConfig, metadata: oauth.AuthorizationServer) {
  const pending: BrowserPending = {
    state: oauth.generateRandomState(),
    nonce: oauth.generateRandomNonce(),
    codeVerifier: oauth.generateRandomCodeVerifier(),
    redirectUri: config.redirectUri,
  };
  const url = providerUrl(metadata.authorization_endpoint!, config);
  const params = {
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: [...new Set(['openid', ...(config.scopes ?? ['profile', 'email'])])].join(' '),
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await oauth.calculatePKCECodeChallenge(pending.codeVerifier),
    code_challenge_method: 'S256',
  };
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return { url: url.href, pending };
}

export function validPending(pending: BrowserPending | undefined): pending is BrowserPending {
  return !!pending && typeof pending.state === 'string' && opaqueValue.test(pending.state) &&
    typeof pending.nonce === 'string' && opaqueValue.test(pending.nonce) &&
    typeof pending.codeVerifier === 'string' && verifierValue.test(pending.codeVerifier) &&
    typeof pending.redirectUri === 'string' && pending.redirectUri.length > 0;
}

export function callbackParameters(callbackUrl: string | URL): URLSearchParams {
  try {
    const params = new URL(callbackUrl).searchParams;
    if (params.has('error')) throw new SsoError('denied');
    return params;
  } catch (cause) {
    if (cause instanceof SsoError) throw cause;
    throw new SsoError('failed', undefined, { cause });
  }
}

export function callbackCode(params: URLSearchParams): string {
  const code = params.get('code');
  if (!code || params.getAll('code').length !== 1) throw new SsoError('failed');
  return code;
}
