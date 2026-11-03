import * as oauth from 'oauth4webapi';
import { SsoError, type LoginConfig } from './types.js';

const requestTimeoutMs = 10_000;

export function requestOptions(config: LoginConfig) {
  return {
    [oauth.allowInsecureRequests]: config.unsafeAllowHttp === true,
    signal: () => AbortSignal.timeout(requestTimeoutMs),
  };
}

export function providerUrl(value: string, config: LoginConfig): URL {
  const url = new URL(value);
  if (url.username || url.password ||
      (url.protocol !== 'https:' && !(config.unsafeAllowHttp && url.protocol === 'http:'))) {
    throw new TypeError('sso: provider endpoints must use HTTPS');
  }
  return url;
}

export function validateConfig(config: LoginConfig): void {
  if (!config.issuer || !config.clientId || !config.redirectUri) {
    throw new TypeError('sso: issuer, clientId and redirectUri are required');
  }
  providerUrl(config.issuer, config);
  new URL(config.redirectUri);
}

export function createDiscovery(config: LoginConfig): () => Promise<oauth.AuthorizationServer> {
  let cached: Promise<oauth.AuthorizationServer> | undefined;
  return () => {
    cached ??= discover(config).catch((cause: unknown) => {
      cached = undefined;
      throw new SsoError('unavailable', undefined, { cause });
    });
    return cached;
  };
}

async function discover(config: LoginConfig): Promise<oauth.AuthorizationServer> {
  const issuer = providerUrl(config.issuer, config);
  const response = await oauth.discoveryRequest(issuer, requestOptions(config));
  const metadata = await oauth.processDiscoveryResponse(issuer, response);
  if (!metadata.authorization_endpoint) throw new TypeError('sso: missing authorization endpoint');
  providerUrl(metadata.authorization_endpoint, config);
  return metadata;
}
