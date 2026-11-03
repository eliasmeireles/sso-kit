/** The part of Storage the loop guard needs; sessionStorage satisfies it. */
export interface AutoLoginStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** Loop guard settings for a login page that redirects without a button. */
export interface AutoLoginOptions {
  /** Storage key; give each app its own when several share an origin. Default "sso-kit.auto-login". */
  key?: string;
  /** How long one automatic attempt suppresses the next. Default 30 000 ms. */
  windowMs?: number;
  /** Default sessionStorage, so the guard is per tab. */
  storage?: AutoLoginStorage;
  /** Clock override for tests. */
  now?: () => number;
}

const DEFAULT_KEY = 'sso-kit.auto-login';
const DEFAULT_WINDOW_MS = 30_000;

/**
 * Decides whether a login page may send the browser straight to the provider.
 *
 * Returns true and records the attempt when no automatic attempt happened in
 * the last window. Returns false when one did: the browser came back without a
 * session (for example a cookie it refused), so the page must show its manual
 * button instead of redirecting in a loop. Also returns false when storage is
 * unavailable. Pages showing a login error must not redirect at all.
 */
export function claimAutoLogin(options: AutoLoginOptions = {}): boolean {
  const key = options.key ?? DEFAULT_KEY;
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const now = (options.now ?? Date.now)();
  try {
    const storage = options.storage ?? globalThis.sessionStorage;
    const last = storage.getItem(key);
    const elapsed = last === null ? Infinity : now - Number(last);
    if (elapsed >= 0 && elapsed < windowMs) return false;
    storage.setItem(key, String(now));
    return true;
  } catch {
    return false;
  }
}
