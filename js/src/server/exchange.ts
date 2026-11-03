import * as oauth from 'oauth4webapi';
import { requestOptions } from '../shared/discovery.js';
import { SsoError, type BrowserPending } from '../shared/types.js';
import type { SsoConfig } from './config.js';
import { identityFrom } from './identity.js';

export async function exchange(config: SsoConfig, metadata: oauth.AuthorizationServer,
  params: URLSearchParams, pending: BrowserPending) {
  try {
    const client: oauth.Client = { client_id: config.clientId, [oauth.clockTolerance]: 0 };
    const validated = oauth.validateAuthResponse(metadata, client, params, oauth.skipStateCheck);
    const methods = metadata.token_endpoint_auth_methods_supported;
    const auth = methods && !methods.includes('client_secret_basic') && methods.includes('client_secret_post')
      ? oauth.ClientSecretPost(config.clientSecret) : oauth.ClientSecretBasic(config.clientSecret);
    const response = await oauth.authorizationCodeGrantRequest(metadata, client, auth,
      validated, pending.redirectUri, pending.codeVerifier, requestOptions(config));
    const result = await oauth.processAuthorizationCodeResponse(metadata, client, response, {
      expectedNonce: pending.nonce,
      requireIdToken: true,
    });
    await oauth.validateApplicationLevelSignature(metadata, response, requestOptions(config));
    const claims = oauth.getValidatedIdTokenClaims(result);
    if (!claims || !result.id_token) throw new TypeError('sso: missing ID token');
    return { identity: identityFrom(claims), idToken: result.id_token };
  } catch (cause) {
    throw new SsoError('failed', undefined, { cause });
  }
}
