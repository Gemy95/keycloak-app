import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import * as KeycloakStrategy from '@exlinc/keycloak-passport';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class KeyCloakStrategy extends PassportStrategy(
  KeycloakStrategy,
  'keycloak',
) {
  constructor(private readonly configService: ConfigService) {
    super({
      host: configService.get<string>('KEYCLOAK_BASE_URL'),
      realm: configService.get<string>('KEYCLOAK_REALM_NAME'),
      clientID: configService.get<string>('KEYCLOAK_CLIENT_ID'),
      clientSecret: configService.get<string>('KEYCLOAK_CLIENT_SECRET'),
      tokenURL: `${configService.get<string>(
        'KEYCLOAK_BASE_URL',
      )}/realms/${configService.get<string>(
        'KEYCLOAK_REALM_NAME',
      )}/protocol/openid-connect/token`,
      authorizationURL: `${configService.get<string>(
        'KEYCLOAK_BASE_URL',
      )}/realms/${configService.get<string>(
        'KEYCLOAK_REALM_NAME',
      )}/protocol/openid-connect/auth`,
      userInfoURL: `${configService.get<string>(
        'KEYCLOAK_BASE_URL',
      )}/realms/${configService.get<string>(
        'KEYCLOAK_REALM_NAME',
      )}/protocol/openid-connect/userinfo`,
      callbackURL: `${configService.get<string>('KEYCLOAK_CALLBACK_URL')}`,
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: any,
  ) {
    try {
      done(null, { profile, accessToken, refreshToken });
    } catch (err) {
      done(err, false);
    }
  }
}
