import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createSsoServer, SsoError, type SsoErrorCode } from './index.js';
import { createProvider } from '../test-support/provider.js';

const hasCode = (code: SsoErrorCode) => (error: unknown) => error instanceof SsoError && error.code === code;

test('start includes OIDC parameters, fresh secrets and S256 PKCE; success returns verified identity and raw token', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const server = createSsoServer({ ...provider.config, policy: { requiredRole: 'app-users', allowedSubjects: ['example-subject'] } });
  assert.equal(provider.state.discoveryRequests, 0);
  const { url, pending } = await server.startLogin();
  const params = new URL(url).searchParams;
  const [state, nonce, verifier] = pending.split('.');
  assert.equal(params.get('client_id'), provider.config.clientId);
  assert.equal(params.get('redirect_uri'), provider.config.redirectUri);
  assert.equal(params.get('response_type'), 'code');
  assert.equal(params.get('scope'), 'openid profile email');
  assert.equal(params.get('code_challenge_method'), 'S256');
  assert.equal(params.get('state'), state);
  assert.equal(params.get('nonce'), nonce);
  assert.equal(params.get('code_challenge'), createHash('sha256').update(verifier!).digest('base64url'));
  for (const secret of [state, nonce, verifier]) assert.match(secret!, /^[A-Za-z0-9_-]{43}$/);
  const result = await server.completeLogin(provider.callback(url), pending);
  assert.deepEqual(result.identity, {
    subject: 'example-subject', email: 'alex@example.com', emailVerified: true,
    name: 'Alex Example', username: 'alex', roles: ['app-users'],
  });
  assert.equal(result.idToken.split('.').length, 3);
  assert.equal(provider.state.jwksRequests, 1);
  assert.notEqual((await server.startLogin()).pending, pending);
  assert.equal(provider.state.discoveryRequests, 1);
});

test('empty name falls back to username; scopes include openid; client_secret_post is supported', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  provider.state.postAuthOnly = true;
  const server = createSsoServer({ ...provider.config, scopes: ['email', 'email'] });
  const login = await server.startLogin();
  assert.equal(new URL(login.url).searchParams.get('scope'), 'openid email');
  const result = await server.completeLogin(provider.callback(login.url, { name: '' }), login.pending);
  assert.equal(result.identity.name, 'alex');
});

test('rejects invalid exchange inputs and untrusted tokens', async (t) => {
  const cases = [
    'wrong verifier', 'wrong code', 'nonce mismatch', 'wrong audience', 'wrong issuer',
    'expired token', 'invalid signature', 'missing token', 'malformed token', 'invalid claim type',
  ];
  for (const name of cases) await t.test(name, async (t) => {
    const provider = await createProvider();
    t.after(() => provider.close());
    const server = createSsoServer(provider.config);
    const login = await server.startLogin();
    const claims = name === 'nonce mismatch' ? { nonce: 'different-nonce' }
      : name === 'wrong audience' ? { aud: 'another-client' }
      : name === 'wrong issuer' ? { iss: 'https://other.example.com' }
      : name === 'expired token' ? { exp: Math.floor(Date.now() / 1000) - 1 }
      : name === 'invalid claim type' ? { email_verified: 'true' } : {};
    const callback = provider.callback(login.url, claims);
    if (name === 'wrong verifier') login.pending = login.pending.split('.').slice(0, 2).join('.') + '.' + 'x'.repeat(43);
    if (name === 'wrong code') callback.searchParams.set('code', 'wrong');
    provider.state.wrongSignature = name === 'invalid signature';
    provider.state.omitIdToken = name === 'missing token';
    provider.state.malformedToken = name === 'malformed token';
    await assert.rejects(server.completeLogin(callback, login.pending), hasCode('failed'));
  });
});

test('callback guards reject denial, missing/garbled pending, state mismatch and missing code before exchange', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const server = createSsoServer(provider.config);
  const { url, pending } = await server.startLogin();
  const callback = provider.callback(url);
  for (const bad of [undefined, '', 'garbled', 'a.b.c', '.nonce.verifier', `${pending}.extra`]) {
    await assert.rejects(server.completeLogin(callback, bad), hasCode('expired'));
  }
  callback.searchParams.set('state', 'wrong');
  await assert.rejects(server.completeLogin(callback, pending), hasCode('expired'));
  callback.searchParams.set('state', 'x'.repeat(43));
  await assert.rejects(server.completeLogin(callback, pending), hasCode('expired'));
  callback.searchParams.delete('state');
  await assert.rejects(server.completeLogin(callback, pending), hasCode('expired'));
  callback.searchParams.set('error', 'access_denied');
  await assert.rejects(server.completeLogin(callback, undefined), hasCode('denied'));
  const missingCode = provider.callback(url);
  missingCode.searchParams.delete('code');
  await assert.rejects(server.completeLogin(missingCode, pending), hasCode('failed'));
  const duplicate = provider.callback(url);
  duplicate.searchParams.append('state', duplicate.searchParams.get('state')!);
  await assert.rejects(server.completeLogin(duplicate, pending), hasCode('expired'));
  await assert.rejects(server.completeLogin('not a URL', pending), hasCode('failed'));
  assert.equal(provider.state.tokenRequests, 0);
});

test('forbidden errors expose only a verified identity for role, subject and email policy failures', async (t) => {
  const cases = [
    { policy: { requiredRole: 'admin' }, claims: {} },
    { policy: { allowedSubjects: ['another-subject'] }, claims: {} },
    { policy: {}, claims: { email_verified: false } },
    { policy: {}, claims: { email: '' } },
  ];
  for (const { policy, claims } of cases) await t.test(JSON.stringify({ policy, claims }), async (t) => {
    const provider = await createProvider();
    t.after(() => provider.close());
    const server = createSsoServer({ ...provider.config, policy });
    const login = await server.startLogin();
    await assert.rejects(server.completeLogin(provider.callback(login.url, claims), login.pending), (error: unknown) => {
      assert.ok(error instanceof SsoError);
      assert.equal(error.code, 'forbidden');
      assert.equal(error.identity?.subject, 'example-subject');
      assert.equal(provider.state.jwksRequests, 1);
      return true;
    });
  });
});
