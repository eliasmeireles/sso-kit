# @eliasmeireles/sso-kit

OIDC Authorization Code + PKCE (S256) helpers matching the Go `sso` and
`ssohttp` packages. ESM, Node 20+ for servers; modern browsers and Chrome MV3
service workers for public clients. The only runtime dependency is
`oauth4webapi`. `jose` is used only by the tests.

## Install

```sh
npm install https://github.com/eliasmeireles/sso-kit/releases/download/js-v0.2.0/eliasmeireles-sso-kit-0.2.0.tgz
```

The release tarball must contain the compiled `dist/` directory. Build with
`npm run build` before packaging a release. Publishing the release is separate
from implementing this package.

## Public API

| Entry | Exports |
| --- | --- |
| `@eliasmeireles/sso-kit/server` | `createSsoServer`, `SsoError`, `pendingCookie`, `clearPendingCookie`, `readCookie`, `loginErrorRedirect` |
| Server types | `SsoConfig`, `SsoServer`, `Policy`, `Identity`, `SsoErrorCode`, `PendingCookieOptions` |
| `@eliasmeireles/sso-kit/browser` | `createBrowserLogin`, `claimAutoLogin`, `SsoError` |
| Browser types | `BrowserLoginConfig`, `BrowserLogin`, `BrowserPending`, `BrowserCallback`, `AutoLoginOptions`, `AutoLoginStorage`, `SsoErrorCode` |

`SsoConfig` contains `issuer`, `clientId`, `clientSecret`, `redirectUri`, optional
`scopes`, and optional `policy: { requiredRole?, allowedSubjects? }`.
`BrowserLoginConfig` has the same public settings, without secret or policy.
Both accept `unsafeAllowHttp?: boolean`, disabled by default, **only for tests
or local development**. All provider endpoints otherwise require HTTPS.

`scopes` defaults to `openid profile email`; custom scopes always include
`openid`. Configure realm-role claims in the provider's ID token. An empty
subject allow list imposes no subject restriction. A nonempty subject, nonempty
e-mail and `email_verified: true` are always required by the server flow.

`createSsoServer(config)` validates local configuration synchronously, then
returns `startLogin()`, `completeLogin(callbackUrl, pending)`, and
`logoutUrl(postLogoutRedirect)`. It makes no network request at construction.
Discovery is shared between concurrent calls, cached after success, and retried
after failure. Discovery, token exchange and JWKS requests have 10-second
timeouts. Logout falls back to the supplied redirect if discovery fails or no
end-session endpoint exists.

`completeLogin` returns `{ identity, idToken }`. Identity has `subject`, `email`,
`emailVerified`, `name`, `username` and `roles`; name falls back to username and
roles come from `realm_access.roles`.

Errors are `SsoError` with `code` equal to `unavailable` (discovery), `denied`
(provider callback error), `expired` (missing/invalid pending or mismatched
state), `failed` (code exchange or invalid token), or `forbidden` (policy).
A `forbidden` error includes the verified `identity`; it must not start a session.

Cookie helpers return header strings for Web `Response` objects. Defaults are
name `sso_pending`, path `/`, `Max-Age=600`, `HttpOnly`, and `SameSite=Lax`.
`secure` is required explicitly. Clearing uses `Max-Age=0`; supply the same
name/path settings. `readCookie(request, name)` returns the raw value or
`undefined`. `loginErrorRedirect(loginPage, code)` preserves query parameters
and fragments on relative or absolute login-page URLs.

## Next.js App Router: confidential backend-for-frontend

Use the Node runtime. Keep the client secret and raw ID token on the server;
never put them in `NEXT_PUBLIC_*` settings. Set `APP_ORIGIN` to a trusted,
configured origin such as `https://app.example.com`, and register its exact
`/auth/callback` URL with the provider.

```ts
// lib/sso.ts (server-only; do not import from Client Components)
import { createSsoServer } from '@eliasmeireles/sso-kit/server';

export const appOrigin = new URL(process.env.APP_ORIGIN!).origin;
export const pendingOptions = { secure: true, path: '/' };
export const sso = createSsoServer({
  issuer: process.env.OIDC_ISSUER!,
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: `${appOrigin}/auth/callback`,
  policy: { requiredRole: 'app-users' },
});
```

```ts
// app/auth/login/route.ts
import { pendingCookie, loginErrorRedirect, SsoError } from '@eliasmeireles/sso-kit/server';
import { sso, pendingOptions, appOrigin } from '@/lib/sso';

export const runtime = 'nodejs';
export async function GET() {
  try {
    const { url, pending } = await sso.startLogin();
    return new Response(null, { status: 303, headers: {
      Location: url,
      'Set-Cookie': pendingCookie(pending, pendingOptions),
      'Cache-Control': 'no-store',
    } });
  } catch (error) {
    const code = error instanceof SsoError ? error.code : 'failed';
    return new Response(null, { status: 303, headers: {
      Location: loginErrorRedirect(`${appOrigin}/login`, code),
      'Cache-Control': 'no-store',
    } });
  }
}
```

The following `startSession` and `endSession` are **application-owned adapters**,
not package exports. `startSession({ identity, idToken })` stores a new session
server-side and returns its opaque, secure HTTP-only session cookie header.
`endSession(request)` revokes that session and returns its clearing cookie header.
Neither adapter should put the raw ID token in a browser-readable cookie.

```ts
// app/auth/callback/route.ts
import { clearPendingCookie, readCookie, loginErrorRedirect, SsoError } from '@eliasmeireles/sso-kit/server';
import { sso, pendingOptions, appOrigin } from '@/lib/sso';
import { startSession } from '@/lib/session';

export const runtime = 'nodejs';
export async function GET(request: Request) {
  const headers = new Headers({ 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', clearPendingCookie(pendingOptions));
  try {
    const result = await sso.completeLogin(request.url, readCookie(request, 'sso_pending'));
    headers.append('Set-Cookie', await startSession(result));
    headers.set('Location', `${appOrigin}/`);
  } catch (error) {
    const code = error instanceof SsoError ? error.code : 'failed';
    headers.set('Location', loginErrorRedirect(`${appOrigin}/login`, code));
  }
  return new Response(null, { status: 303, headers });
}
```

```ts
// app/auth/logout/route.ts
import { clearPendingCookie } from '@eliasmeireles/sso-kit/server';
import { sso, pendingOptions, appOrigin } from '@/lib/sso';
import { endSession } from '@/lib/session';

export const runtime = 'nodejs';
export async function POST(request: Request) {
  if (request.headers.get('origin') !== appOrigin) {
    return new Response('Forbidden', { status: 403 });
  }
  const headers = new Headers({ 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', await endSession(request));
  headers.append('Set-Cookie', clearPendingCookie(pendingOptions));
  headers.set('Location', await sso.logoutUrl(`${appOrigin}/login`));
  return new Response(null, { status: 303, headers });
}
```

Forward the stored raw `idToken` from the BFF to a private Go API over your
trusted, authenticated backend channel. For example, send it as the bearer
credential expected by that API. The API must independently call
`sso.Verifier.Verify` with the BFF client ID as an accepted audience and apply
its own policy. The token expires: reauthenticate when necessary. This package
does not implement application sessions or refresh tokens.

## Browser / Next.js SPA: public client

Use a separate public client registration. This entry imports no Node built-ins
and never exchanges a code or verifies an identity. Provider discovery must
allow your application's origin through CORS.

```ts
import { createBrowserLogin, type BrowserPending } from '@eliasmeireles/sso-kit/browser';

const login = createBrowserLogin({
  issuer: 'https://sso.example.com/realms/main',
  clientId: 'example-public-app',
  redirectUri: 'https://app.example.com/callback',
});

// Run in a browser event handler, not during server rendering.
export async function startLogin() {
  const { url, pending } = await login.start();
  sessionStorage.setItem('sso_pending', JSON.stringify(pending));
  location.assign(url);
}

// Run once on the callback page; handle SsoError in your app's error UI.
export async function finishLogin() {
  const saved = sessionStorage.getItem('sso_pending');
  sessionStorage.removeItem('sso_pending');
  const pending: BrowserPending | undefined = saved ? JSON.parse(saved) : undefined;
  const result = login.readCallback(location.href, pending);
  history.replaceState(null, '', location.pathname);
  const response = await fetch('/api/auth/exchange', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ code: result.code, code_verifier: result.codeVerifier,
      nonce: result.nonce, redirect_uri: result.redirectUri }),
  });
  if (!response.ok) throw new Error('Login failed');
}
```

The `/api/auth/exchange` contract above is application-owned. The Go backend
creates a public `sso.Client`, constructs `sso.Pending{Nonce: nonce, Verifier:
codeVerifier}`, and calls `Complete(ctx, code, pending,
sso.WithRedirectURL(redirectUri))`. Allow-list redirect URIs on the backend,
validate request origin/CSRF as appropriate for its session mechanism, and
configure the provider with exact redirects. Never trust a browser-supplied
identity or substitute `readCallback` for backend token verification.

For MV3, bundle the browser entry with your extension; use the `identity` and
`storage` permissions and host permissions for your issuer and backend.
Register the exact URL returned by `chrome.identity.getRedirectURL('callback')`.

```ts
import { createBrowserLogin, type BrowserPending } from '@eliasmeireles/sso-kit/browser';

const login = createBrowserLogin({
  issuer: 'https://sso.example.com/realms/main',
  clientId: 'example-extension',
  redirectUri: chrome.identity.getRedirectURL('callback'),
});

export async function signIn() {
  const { url, pending } = await login.start();
  await chrome.storage.session.set({ sso_pending: pending });
  try {
    const callback = await chrome.identity.launchWebAuthFlow({ url, interactive: true });
    const stored = await chrome.storage.session.get('sso_pending');
    await chrome.storage.session.remove('sso_pending');
    if (!callback) throw new Error('Login cancelled');
    const result = login.readCallback(callback, stored.sso_pending as BrowserPending | undefined);
    const response = await fetch('https://api.example.com/auth/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: result.code, code_verifier: result.codeVerifier,
        nonce: result.nonce, redirect_uri: result.redirectUri }),
    });
    if (!response.ok) throw new Error('Login failed');
    // Consume the backend's application-session response according to your app's contract.
  } finally {
    await chrome.storage.session.remove('sso_pending');
  }
}
```

## Login page without a button

A login page can send the browser straight to the provider instead of showing
a "Sign in" button. Two rules keep this from looping:

- Never redirect when the page shows a login error (`?error=forbidden`, a
  denied consent and so on); show the message and a manual button.
- Redirect at most once per short window. If the browser comes back without a
  session a few seconds later (a refused cookie, for example), show the button.

`claimAutoLogin` implements the second rule with a timestamp in
`sessionStorage`. It works in any page, including those that start the flow on
a backend route:

```ts
import { claimAutoLogin } from '@eliasmeireles/sso-kit/browser';

// In a client component or script, after checking there is no session.
if (!new URLSearchParams(location.search).has('error') &&
    claimAutoLogin({ key: 'example-app.auto-login' })) {
  location.replace('/auth/login');
} else {
  showLoginButton();
}
```

It returns `false` when storage is unavailable, so the page falls back to the
button. The default window is 30 seconds; a person typing a password and an
authenticator code takes longer than a redirect that bounces straight back.

## Security notes

- Register exact login and post-logout redirect URIs. Enable standard code flow,
  PKCE S256 and the realm-role mapper on the provider; disable implicit flow and
  password grants. Client secrets belong only in confidential server clients.
- Server callbacks check state with constant-time comparison, then validate
  ID-token signature via JWKS, issuer, audience, expiration (no clock grace)
  and nonce before applying policy. Keep server clocks synchronized.
- Server pending values use Go's `state.nonce.verifier` serialization. The cookie
  is short-lived but not encrypted/signed by this library. Use HTTPS, `Secure`,
  HTTP-only cookies and a trusted host; `__Host-` cookie names can be configured
  with path `/` and secure enabled when stronger cookie scoping is needed.
- Clear pending state on every callback, including errors. Server helpers do
  not consume storage automatically. Browser callers must delete stored pending
  state after use/cancellation and enforce a short lifetime; `BrowserPending`
  has no timestamp. One storage key/cookie supports one outstanding login.
- Never log pending secrets, codes, client secrets or ID tokens. Keep browser
  pending state in session storage, restrict extension storage to trusted
  contexts, and protect the application against XSS.
- The browser callback only supplies code-exchange inputs. The trusted backend
  verifies the ID token and authorizes the identity before creating a session.
  Protect session-changing endpoints against CSRF and restrict CORS origins.

## Development

```sh
npm ci
npm test
npm run build
```

Tests use a loopback HTTP OIDC provider on a random port with RS256 tokens,
JWKS and PKCE/client-authentication checks. No external provider or network
download is needed after dependencies are installed. A sandbox that prohibits
listening sockets can run the same handler/signature tests with
`SSO_KIT_TEST_TRANSPORT=memory npm test`; CI uses the real HTTP transport.
