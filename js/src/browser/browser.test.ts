import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createBrowserLogin, SsoError, type BrowserPending, type SsoErrorCode } from './index.js';
import { createProvider } from '../test-support/provider.js';

const hasCode = (code: SsoErrorCode) => (error: unknown) => error instanceof SsoError && error.code === code;

test('browser starts a public PKCE flow and reads callback without exchanging tokens', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const { clientSecret: _, ...config } = provider.config;
  const browser = createBrowserLogin(config);
  const { url, pending } = await browser.start();
  const params = new URL(url).searchParams;
  assert.equal(params.get('client_id'), config.clientId);
  assert.equal(params.get('redirect_uri'), config.redirectUri);
  assert.equal(params.get('state'), pending.state);
  assert.equal(params.get('nonce'), pending.nonce);
  assert.equal(params.get('code_challenge_method'), 'S256');
  assert.equal(params.get('code_challenge'), createHash('sha256').update(pending.codeVerifier).digest('base64url'));
  assert.equal(params.get('client_secret'), null);
  const callback = provider.callback(url);
  assert.deepEqual(browser.readCallback(callback, JSON.parse(JSON.stringify(pending)) as BrowserPending), {
    code: callback.searchParams.get('code'), codeVerifier: pending.codeVerifier,
    nonce: pending.nonce, redirectUri: config.redirectUri,
  });
  assert.equal(provider.state.tokenRequests, 0);
  assert.notDeepEqual((await browser.start()).pending, pending);
  assert.equal(provider.state.discoveryRequests, 1);
});

test('browser refuses missing or malformed pending, mismatched state, denial and missing code', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const browser = createBrowserLogin(provider.config);
  const { url, pending } = await browser.start();
  const callback = provider.callback(url);
  for (const bad of [undefined, {} as BrowserPending, { ...pending, nonce: '' },
    { ...pending, codeVerifier: '' }, { ...pending, redirectUri: 'https://other.example.com' }]) {
    assert.throws(() => browser.readCallback(callback, bad), hasCode('expired'));
  }
  callback.searchParams.set('state', 'wrong');
  assert.throws(() => browser.readCallback(callback, pending), hasCode('expired'));
  callback.searchParams.delete('state');
  assert.throws(() => browser.readCallback(callback, pending), hasCode('expired'));
  callback.searchParams.set('error', 'access_denied');
  assert.throws(() => browser.readCallback(callback, undefined), hasCode('denied'));
  callback.searchParams.delete('error');
  callback.searchParams.set('state', pending.state);
  callback.searchParams.delete('code');
  assert.throws(() => browser.readCallback(callback, pending), hasCode('failed'));
  callback.searchParams.append('state', pending.state);
  assert.throws(() => browser.readCallback(callback, pending), hasCode('expired'));
  assert.equal(provider.state.tokenRequests, 0);
});

test('browser supports MV3 callback URI and retries provider discovery', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const browser = createBrowserLogin({ ...provider.config, redirectUri: 'https://example-extension.chromiumapp.org/callback', scopes: ['email'] });
  provider.state.discoveryAvailable = false;
  await assert.rejects(browser.start(), hasCode('unavailable'));
  provider.state.discoveryAvailable = true;
  const login = await browser.start();
  assert.equal(new URL(login.url).searchParams.get('scope'), 'openid email');
  assert.equal(browser.readCallback(provider.callback(login.url), login.pending).redirectUri,
    'https://example-extension.chromiumapp.org/callback');
  assert.throws(() => createBrowserLogin({ ...provider.config, unsafeAllowHttp: false }), /HTTPS/);
});
