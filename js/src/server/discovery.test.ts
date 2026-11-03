import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSsoServer, SsoError } from './index.js';
import { createProvider } from '../test-support/provider.js';

const unavailable = (error: unknown) => error instanceof SsoError && error.code === 'unavailable';

test('lazy discovery retries failures, then shares and caches successful discovery', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  provider.state.discoveryAvailable = false;
  const server = createSsoServer(provider.config);
  assert.equal(provider.state.discoveryRequests, 0);
  await assert.rejects(server.startLogin(), unavailable);
  await assert.rejects(server.startLogin(), unavailable);
  assert.equal(provider.state.discoveryRequests, 2);
  provider.state.discoveryAvailable = true;
  await Promise.all([server.startLogin(), server.startLogin(), server.startLogin()]);
  assert.equal(provider.state.discoveryRequests, 3);
  provider.state.discoveryAvailable = false;
  await server.startLogin();
  assert.equal(provider.state.discoveryRequests, 3);
});

test('discovery failure in completeLogin is unavailable', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const login = await createSsoServer(provider.config).startLogin();
  provider.state.discoveryAvailable = false;
  await assert.rejects(createSsoServer(provider.config).completeLogin(provider.callback(login.url), login.pending), unavailable);
});

test('logout URL preserves endpoint parameters and adds client and redirect', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  const redirect = 'https://app.example.com/login';
  const url = new URL(await createSsoServer(provider.config).logoutUrl(redirect));
  assert.equal(url.pathname, '/logout');
  assert.equal(url.searchParams.get('existing'), 'value');
  assert.equal(url.searchParams.get('client_id'), provider.config.clientId);
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), redirect);
});

test('logout falls back without endpoint, on failed discovery and on network failure', async () => {
  const provider = await createProvider();
  const redirect = 'https://app.example.com/login';
  try {
    provider.state.hasLogout = false;
    assert.equal(await createSsoServer(provider.config).logoutUrl(redirect), redirect);
    provider.state.discoveryAvailable = false;
    assert.equal(await createSsoServer(provider.config).logoutUrl(redirect), redirect);
  } finally {
    await provider.close();
  }
  const server = createSsoServer(provider.config);
  assert.equal(await server.logoutUrl(redirect), redirect);
  await assert.rejects(server.startLogin(), unavailable);
});

test('HTTP requires explicit development opt-in; configuration is validated without discovery', async (t) => {
  const provider = await createProvider();
  t.after(() => provider.close());
  assert.throws(() => createSsoServer({ ...provider.config, unsafeAllowHttp: false }), /HTTPS/);
  assert.throws(() => createSsoServer({ ...provider.config, clientSecret: '' }), /clientSecret/);
  assert.throws(() => createSsoServer({ ...provider.config, clientId: '' }), /clientId/);
  assert.equal(provider.state.discoveryRequests, 0);
});
