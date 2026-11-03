import { callbackCode, callbackParameters, startAuthorization, validPending } from '../shared/authorization.js';
import { createDiscovery, validateConfig } from '../shared/discovery.js';
import { SsoError, type BrowserPending, type LoginConfig } from '../shared/types.js';

export { SsoError, type SsoErrorCode, type BrowserPending } from '../shared/types.js';
/** Public client settings; this flow never accepts a client secret or exchanges codes. */
export type BrowserLoginConfig = LoginConfig;
/** Validated callback values to send to the trusted backend for code exchange. */
export type BrowserCallback = Omit<BrowserPending, 'state'> & { code: string };

/** Browser/MV3 login operations using Web APIs only. */
export interface BrowserLogin {
  /** Creates a login URL and secrets for sessionStorage or chrome.storage.session. */
  start(): Promise<{ url: string; pending: BrowserPending }>;
  /** Checks state and returns code exchange inputs; it does not authenticate the user. */
  readCallback(callbackUrl: string | URL, pending: BrowserPending | undefined): BrowserCallback;
}

/** Creates a public-client flow. Discovery requires provider CORS access from the browser. */
export function createBrowserLogin(config: BrowserLoginConfig): BrowserLogin {
  config = structuredClone(config);
  validateConfig(config);
  const discover = createDiscovery(config);
  return {
    async start() {
      return startAuthorization(config, await discover());
    },
    readCallback(callbackUrl, pending) {
      const params = callbackParameters(callbackUrl);
      if (!validPending(pending) || pending.redirectUri !== config.redirectUri ||
          params.getAll('state').length !== 1 || params.get('state') !== pending.state) {
        throw new SsoError('expired');
      }
      return {
        code: callbackCode(params),
        codeVerifier: pending.codeVerifier,
        nonce: pending.nonce,
        redirectUri: pending.redirectUri,
      };
    },
  };
}
