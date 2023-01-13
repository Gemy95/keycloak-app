export type credentialsType = { value: string };

export interface IKeycloakUser {
  id?: string;
  name?: string;
  email?: string;
  countryCode?: string;
  mobile?: string;
  password?: any;
  enabled?: boolean;
  username?: string;
  groups?: string[];
  credentials?: credentialsType[];
}
