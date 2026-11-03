import { SsoError, type Identity, type Policy } from '../shared/types.js';

function stringClaim(value: unknown): string {
  if (value == null) return '';
  if (typeof value !== 'string') throw new TypeError('sso: invalid string claim');
  return value;
}

export function identityFrom(claims: Record<string, unknown>): Identity {
  const realm = claims.realm_access;
  if (realm != null && (typeof realm !== 'object' || Array.isArray(realm))) {
    throw new TypeError('sso: invalid realm_access claim');
  }
  const roles = (realm as { roles?: unknown } | null | undefined)?.roles ?? [];
  if (!Array.isArray(roles) || !roles.every((role: unknown) => typeof role === 'string')) {
    throw new TypeError('sso: invalid roles claim');
  }
  if (claims.email_verified != null && typeof claims.email_verified !== 'boolean') {
    throw new TypeError('sso: invalid email_verified claim');
  }
  const username = stringClaim(claims.preferred_username);
  return {
    subject: stringClaim(claims.sub),
    email: stringClaim(claims.email),
    emailVerified: claims.email_verified === true,
    name: stringClaim(claims.name) || username,
    username,
    roles: [...roles],
  };
}

export function authorize(identity: Identity, policy: Policy = {}): void {
  if (!identity.subject || !identity.email || !identity.emailVerified ||
      (policy.requiredRole && !identity.roles.includes(policy.requiredRole)) ||
      (policy.allowedSubjects?.length && !policy.allowedSubjects.includes(identity.subject))) {
    throw new SsoError('forbidden', identity);
  }
}
