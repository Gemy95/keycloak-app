import { Module } from '@nestjs/common';
import { UserClientService } from './user.client.service';
import { UserClientResolver } from './user.client.resolver';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { PrismaService } from '../prisma.service';

@Module({
  imports: [KeycloakModule],
  providers: [UserClientResolver, UserClientService, PrismaService],
})
export class UserClientModule {}
