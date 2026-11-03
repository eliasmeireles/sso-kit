/** Restricts authenticated identities by realm role and subject. */
export type Policy = {
  requiredRole?: string;
  allowedSubjects?: string[];
};

/** Claims of a verified ID token, with name falling back to username. */
export type Identity = {
  subject: string;
  email: string;
  emailVerified: boolean;
  name: string;
  username: string;
  roles: string[];
};

/** Login failure codes shared with Go's ssohttp package. */
export type SsoErrorCode = 'unavailable' | 'denied' | 'expired' | 'forbidden' | 'failed';

/** An SSO failure; forbidden errors include the verified identity. */
export class SsoError extends Error {
  constructor(
    public readonly code: SsoErrorCode,
    public readonly identity?: Identity,
    options?: ErrorOptions,
  ) {
    super(`sso: ${code}`, options);
    this.name = 'SsoError';
  }
}

/** Public OIDC settings shared by server and browser flows. */
export type LoginConfig = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Defaults to openid, profile, email. The openid scope is always included. */
  scopes?: string[];
  /** Tests/local development only: permits HTTP issuer and provider endpoints. */
  unsafeAllowHttp?: boolean;
};

/** Per-login secrets to persist only until the callback has been consumed. */
export type BrowserPending = {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
};
