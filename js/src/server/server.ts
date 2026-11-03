import { callbackCode, callbackParameters, startAuthorization } from '../shared/authorization.js';
import { createDiscovery, providerUrl, validateConfig } from '../shared/discovery.js';
import { SsoError, type Identity } from '../shared/types.js';
import type { SsoConfig } from './config.js';
import { exchange } from './exchange.js';
import { authorize } from './identity.js';
import { readPending } from './pending.js';

/** Confidential-client login and logout operations; discovery is lazy. */
export interface SsoServer {
  /** Starts a login, returning its URL and Go-compatible HTTP-only cookie value. */
  startLogin(): Promise<{ url: string; pending: string }>;
  /** Validates the callback, exchanges the code, verifies the ID token and applies policy. */
  completeLogin(callbackUrl: string | URL, pending: string | undefined): Promise<{ identity: Identity; idToken: string }>;
  /** Builds the provider logout URL, falling back to the supplied redirect. */
  logoutUrl(postLogoutRedirect: string): Promise<string>;
}

/** Creates a confidential OIDC client without contacting the provider. */
export function createSsoServer(config: SsoConfig): SsoServer {
  config = structuredClone(config);
  validateConfig(config);
  if (!config.clientSecret) throw new TypeError('sso: clientSecret is required');
  const discover = createDiscovery(config);
  return {
    async startLogin() {
      const { url, pending } = await startAuthorization(config, await discover());
      return { url, pending: `${pending.state}.${pending.nonce}.${pending.codeVerifier}` };
    },
    async completeLogin(callbackUrl, value) {
      const params = callbackParameters(callbackUrl);
      if (params.getAll('state').length !== 1) {
        throw new SsoError('expired');
      }
      const pending = readPending(value, params.get('state'), config.redirectUri);
      callbackCode(params);
      const result = await exchange(config, await discover(), params, pending);
      authorize(result.identity, config.policy);
      return result;
    },
    async logoutUrl(postLogoutRedirect) {
      try {
        const metadata = await discover();
        if (!metadata.end_session_endpoint) return postLogoutRedirect;
        const url = providerUrl(metadata.end_session_endpoint, config);
        url.searchParams.set('client_id', config.clientId);
        url.searchParams.set('post_logout_redirect_uri', postLogoutRedirect);
        return url.href;
      } catch {
        return postLogoutRedirect;
      }
    },
  };
}
