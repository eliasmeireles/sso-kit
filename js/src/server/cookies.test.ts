import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pendingCookie, clearPendingCookie, readCookie, loginErrorRedirect } from './index.js';

test('pending and clearing cookies have matching scopes and secure defaults', () => {
  assert.equal(pendingCookie('state.nonce.verifier', { secure: true }),
    'sso_pending=state.nonce.verifier; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure');
  const options = { name: 'login_pending', path: '/auth', secure: false, maxAge: 90 };
  assert.equal(pendingCookie('value', options),
    'login_pending=value; Path=/auth; Max-Age=90; HttpOnly; SameSite=Lax');
  assert.equal(clearPendingCookie(options),
    'login_pending=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax');
  assert.equal(clearPendingCookie({ secure: true }),
    'sso_pending=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure');
});

test('cookie helpers reject header injection and invalid lifetimes', () => {
  assert.throws(() => pendingCookie('a; admin=true', { secure: true }));
  assert.throws(() => pendingCookie('a\r\nb', { secure: true }));
  assert.throws(() => pendingCookie('a', { secure: true, name: 'name=value' }));
  assert.throws(() => pendingCookie('a', { secure: true, path: '/; Domain=example.com' }));
  assert.throws(() => pendingCookie('a', { secure: true, maxAge: 1.5 }));
  assert.throws(() => pendingCookie('a', { secure: true, maxAge: -1 }));
});

test('readCookie returns exact raw values and undefined for absent cookies', () => {
  const request = new Request('https://app.example.com', { headers: { cookie: 'other=one; sso_pending=a.b.c; token=x=y' } });
  assert.equal(readCookie(request, 'sso_pending'), 'a.b.c');
  assert.equal(readCookie(request, 'token'), 'x=y');
  assert.equal(readCookie(request, 'pending'), undefined);
  assert.equal(readCookie(new Request('https://app.example.com'), 'sso_pending'), undefined);
});

test('loginErrorRedirect handles relative and absolute URLs, existing query and hash', () => {
  assert.equal(loginErrorRedirect('/login', 'denied'), '/login?error=denied');
  assert.equal(loginErrorRedirect('/login?next=%2Fapp&error=failed#form', 'expired'), '/login?next=%2Fapp&error=expired#form');
  assert.equal(loginErrorRedirect('https://app.example.com/login', 'unavailable'), 'https://app.example.com/login?error=unavailable');
});
