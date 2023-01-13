import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { KeycloakAuthService } from '../auth/keycloak-auth.service';
import { GqlExecutionContext } from '@nestjs/graphql';
import * as jsonwebtoken from 'jsonwebtoken';
import { Reflector } from '@nestjs/core';
import {
  META_SKIP_AUTH,
  META_UNPROTECTED,
} from 'nest-keycloak-connect/decorators/public.decorator';

@Injectable()
export class GraphQlKeycloakAuthGuard implements CanActivate {
  constructor(
    private keycloakAuthService: KeycloakAuthService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const gqlCtx = GqlExecutionContext?.create(context);
    const request = gqlCtx?.getContext()?.req;

    const Unprotected = this.reflector.getAllAndOverride<boolean>(
      META_UNPROTECTED,
      [context.getClass(), context.getHandler()],
    );
    const Public = this.reflector.getAllAndOverride<boolean>(META_SKIP_AUTH, [
      context.getClass(),
      context.getHandler(),
    ]);

    // If unprotected is set skip Keycloak authentication
    if (Unprotected && Public) {
      return true;
    }

    const header = request?.header('Authorization');
    if (!header) {
      throw new HttpException(
        'Authorization: Bearer <token> header missing',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const parts = header?.split(' ');
    if (parts?.length !== 2 || parts[0] !== 'Bearer') {
      throw new HttpException(
        'Authorization: Bearer <token> header invalid',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const token = parts[1];

    const jwtPayload = jsonwebtoken?.decode(token);

    if (jwtPayload && jwtPayload?.exp < Date.now() / 1000) {
      throw new UnauthorizedException('Sorry, Expired Token');
    }

    try {
      const response = await this.keycloakAuthService.authorize(token);
      request.user = response;
      request.accessTokenJWT = token;
      return true;
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }
}
