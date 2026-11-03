/** Pending cookie settings. Use secure: true on HTTPS deployments. */
export type PendingCookieOptions = {
  name?: string;
  path?: string;
  secure: boolean;
  maxAge?: number;
};

const cookieName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const cookieValue = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;
const cookiePath = /^[\x20-\x3A\x3C-\x7E]+$/;

/** Returns a Set-Cookie header with HttpOnly, SameSite=Lax and a 600-second default lifetime. */
export function pendingCookie(value: string, options: PendingCookieOptions): string {
  const { name = 'sso_pending', path = '/', secure, maxAge = 600 } = options;
  if (!cookieName.test(name) || !cookieValue.test(value) || !cookiePath.test(path) ||
      !path.startsWith('/') || !Number.isSafeInteger(maxAge) || maxAge < 0) {
    throw new TypeError('sso: invalid pending cookie');
  }
  return `${name}=${value}; Path=${path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** Expires the pending cookie; use the same name, path and secure setting used to create it. */
export function clearPendingCookie(options: PendingCookieOptions): string {
  return pendingCookie('', { ...options, maxAge: 0 });
}

/** Reads a raw cookie value from a Web Request, or undefined when absent. */
export function readCookie(request: Request, name: string): string | undefined {
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    return part.slice(separator + 1).trim();
  }
  return undefined;
}
