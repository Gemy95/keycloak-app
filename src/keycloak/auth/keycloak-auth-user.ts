export class IKeycloakAuthUser {
  id: string;
  email: string;
  username: string;

  constructor(values) {
    this.id = values.sub;
    this.email = values.email;
    this.username = values.preferred_username;
  }
}
