import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';
import { PrismaService } from '../prisma.service';
import { KeyCloakStrategy } from './auth/keycloak-auth-strategy';
import { KeycloakController } from './auth/keycloak-auth.controller';
import { KeycloakAuthService } from './auth/keycloak-auth.service';
import { KeycloakConfigService } from './config/keycloak.config.service';

@Module({
  imports: [ConfigModule, HttpModule],
  controllers: [KeycloakController],
  providers: [
    KeycloakConfigService,
    KeycloakAuthService,
    PrismaService,
    // KeyCloakStrategy, not used till now
  ],
  exports: [KeycloakConfigService, KeycloakAuthService],
})
export class KeycloakModule {}
