import type { LoginConfig, Policy } from '../shared/types.js';

/** Settings for a confidential OIDC client. Keep clientSecret on the server. */
export type SsoConfig = LoginConfig & {
  clientSecret: string;
  policy?: Policy;
};
