import { createTransport } from './transport.js';
import { createHash } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import type { SsoConfig } from '../server/index.js';

const signingKeys = generateKeyPair('RS256');
const unrelatedKeys = generateKeyPair('RS256');
const clientId = 'example-bff';
const clientSecret = 'fictional-test-secret';
const redirectUri = 'https://app.example.com/auth/callback';

type Grant = { params: URLSearchParams; claims: JWTPayload };

/** Local OIDC fixture that validates client authentication, redirect URI and PKCE. */
export async function createProvider() {
  const keys = await signingKeys;
  const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'example-key', alg: 'RS256', use: 'sig' };
  const grants = new Map<string, Grant>();
  const state = {
    discoveryAvailable: true, hasLogout: true, wrongSignature: false,
    omitIdToken: false, malformedToken: false, postAuthOnly: false,
    discoveryRequests: 0, tokenRequests: 0, jwksRequests: 0,
  };
  const transport = await createTransport(handle);
  const issuer = transport.origin;

  async function token(req: Request) {
    state.tokenRequests++;
    const params = new URLSearchParams(await req.text());
    const code = params.get('code') ?? '';
    const grant = grants.get(code);
    const basic = req.headers.get('authorization') ?? '';
    const credentials = Buffer.from(basic.slice(6), 'base64').toString().split(':')
      .map((value) => decodeURIComponent(value.replaceAll('+', ' ')));
    const authenticated = state.postAuthOnly
      ? params.get('client_id') === clientId && params.get('client_secret') === clientSecret
      : basic.startsWith('Basic ') && credentials[0] === clientId && credentials[1] === clientSecret;
    const challenge = createHash('sha256').update(params.get('code_verifier') ?? '').digest('base64url');
    if (!authenticated || !grant || params.get('grant_type') !== 'authorization_code' ||
        params.get('redirect_uri') !== grant.params.get('redirect_uri') ||
        challenge !== grant.params.get('code_challenge')) {
      return json(400, { error: 'invalid_grant' });
    }
    grants.delete(code);
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: issuer, aud: clientId, sub: 'example-subject', iat: now, exp: now + 300,
      nonce: grant.params.get('nonce'), email: 'alex@example.com', email_verified: true,
      name: 'Alex Example', preferred_username: 'alex', realm_access: { roles: ['app-users'] },
      ...grant.claims,
    };
    const signingKey = state.wrongSignature ? (await unrelatedKeys).privateKey : keys.privateKey;
    const idToken = state.malformedToken ? 'not.a.jwt' : await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'example-key' }).sign(signingKey);
    return json(200, {
      access_token: 'fictional-access-token', token_type: 'Bearer', expires_in: 300,
      ...(!state.omitIdToken && { id_token: idToken }),
    });
  }

  async function handle(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname;
    if (path === '/.well-known/openid-configuration') {
      state.discoveryRequests++;
      if (!state.discoveryAvailable) return json(503, { error: 'unavailable' });
      return json(200, {
        issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`, response_types_supported: ['code'], subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: [state.postAuthOnly ? 'client_secret_post' : 'client_secret_basic'],
        ...(state.hasLogout && { end_session_endpoint: `${issuer}/logout?existing=value` }),
      });
    }
    if (path === '/jwks') {
      state.jwksRequests++;
      return json(200, { keys: [publicJwk] });
    }
    if (path === '/token' && req.method === 'POST') return token(req);
    return json(404, { error: 'not_found' });
  }

  return {
    state,
    config: { issuer, clientId, clientSecret, redirectUri, unsafeAllowHttp: true } satisfies SsoConfig,
    callback(authorizationUrl: string, claims: JWTPayload = {}) {
      const params = new URL(authorizationUrl).searchParams;
      const code = crypto.randomUUID();
      grants.set(code, { params, claims });
      const callback = new URL(params.get('redirect_uri')!);
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', params.get('state')!);
      return callback;
    },
    close: transport.close,
  };
}

function json(status: number, body: unknown): Response {
  return Response.json(body, { status });
}
