import { test } from 'node:test';
import assert from 'node:assert/strict';
import { claimAutoLogin, type AutoLoginStorage } from './index.js';

function memoryStorage(): AutoLoginStorage & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => { items.set(key, value); },
  };
}

test('auto login is allowed once per window and again after it', () => {
  const storage = memoryStorage();
  let now = 10;
  const claim = () => claimAutoLogin({ storage, now: () => now });
  assert.equal(claim(), true);
  now += 5_000;
  assert.equal(claim(), false, 'a quick return without a session must not redirect again');
  now += 30_000;
  assert.equal(claim(), true);
});

test('auto login keys are independent and the window is configurable', () => {
  const storage = memoryStorage();
  const now = () => 2_000_000;
  assert.equal(claimAutoLogin({ storage, now, key: 'app-a' }), true);
  assert.equal(claimAutoLogin({ storage, now, key: 'app-b' }), true);
  assert.equal(claimAutoLogin({ storage, now, key: 'app-a' }), false);
  assert.equal(claimAutoLogin({ storage, now: () => 2_000_100, key: 'app-c', windowMs: 50 }), true);
  assert.equal(claimAutoLogin({ storage, now: () => 2_000_200, key: 'app-c', windowMs: 50 }), true);
});

test('auto login ignores garbage or future timestamps and fails closed without storage', () => {
  const storage = memoryStorage();
  storage.items.set('sso-kit.auto-login', 'not-a-number');
  assert.equal(claimAutoLogin({ storage, now: () => 10 }), true);
  storage.items.set('sso-kit.auto-login', '999999');
  assert.equal(claimAutoLogin({ storage, now: () => 10 }), true);
  const broken: AutoLoginStorage = {
    getItem: () => { throw new Error('denied'); },
    setItem: () => { throw new Error('denied'); },
  };
  assert.equal(claimAutoLogin({ storage: broken }), false);
});
