import { Injectable } from '@nestjs/common';
import { CreateUserInput } from './dto/create-user.input';
import { LoginUserInput } from './dto/login.input';
import { UpdateUserInput } from './dto/update-user.input';
import { nanoid } from 'nanoid';
import { ResetPasswordUserInput } from './dto/reset-password.input';
import { KeycloakAuthService } from '../keycloak/auth/keycloak-auth.service';
import { PrismaService } from '../prisma.service';
import { IKeycloakAuthUser } from '../keycloak/auth/keycloak-auth-user';

@Injectable()
export class UserClientService {
  constructor(
    private prisma: PrismaService,
    private keycloakAuthService: KeycloakAuthService,
  ) {}

  create(createUserInput: CreateUserInput) {
    return this.prisma.user.create({
      data: {
        ...createUserInput,
      },
    });
  }

  findOne(id: number) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  register(createUserInput: CreateUserInput) {
    const newUser = createUserInput;
    newUser['enabled'] = true;
    newUser['username'] = nanoid();
    newUser['credentials'] = [
      {
        type: 'password',
        temporary: false,
        value: newUser.password,
      },
    ];

    newUser['attributes'] = {
      mobile: newUser.mobile,
      countryCode: newUser.countryCode,
    };

    newUser['groups'] = ['beyond-plus-users-group'];

    delete newUser.countryCode;
    delete newUser.password;
    delete newUser.mobile;

    return this.keycloakAuthService.registerUser(newUser);
  }

  login(loginUserInput: LoginUserInput) {
    return this.keycloakAuthService.userLogin(
      loginUserInput.username,
      loginUserInput.password,
    );
  }
  logout(user: IKeycloakAuthUser) {
    return this.keycloakAuthService.logout(user.id);
  }

  resetPassword(
    resetPasswordUserInput: ResetPasswordUserInput,
    user: IKeycloakAuthUser,
  ) {
    return this.keycloakAuthService.resetPassword(
      user,
      {
        newPassword: resetPasswordUserInput.newPassword,
        oldPassword: resetPasswordUserInput.oldPassword,
      },
      false,
    );
  }

  userAccessTokenFromRefreshToken(refreshToken: string) {
    return this.keycloakAuthService.userAccessTokenFromRefreshToken(
      refreshToken,
    );
  }

  update(id: number, updateUserInput: UpdateUserInput) {
    return this.prisma.user.update({
      data: {
        ...updateUserInput,
      },
      where: {
        id: updateUserInput.id,
      },
    });
  }
}
