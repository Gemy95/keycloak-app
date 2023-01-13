import { Resolver, Query, Mutation, Args } from '@nestjs/graphql';
import { UserClientService } from './user.client.service';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import {
  Public,
  Resource,
  RoleMatchingMode,
  Roles,
  Scopes,
  Unprotected,
} from 'nest-keycloak-connect';
import { UseGuards } from '@nestjs/common';
import { LoginUserInput } from './dto/login.input';
import { ResetPasswordUserInput } from './dto/reset-password.input';
import { CurrentUser } from '../helpers/user.decorator';
import { IKeycloakAuthUser } from '../keycloak/auth/keycloak-auth-user';

@Resource('beyond-plus-resource')
@Resolver('User')
export class UserClientResolver {
  constructor(private readonly userClientService: UserClientService) {}

  @Mutation('createUser')
  create(@Args('createUserInput') createUserInput: CreateUserInput) {
    return this.userClientService.create(createUserInput);
  }

  // @Roles({ roles: ['admin_role'], mode: RoleMatchingMode.ANY })
  // @Scopes('view')
  // @Query('test')
  // test(@CurrentUser() user: IKeycloakAuthUser) {
  //   console.log('user=', user);
  //   return 'success';
  // }

  @Public()
  @Mutation('register')
  register(@Args('createUserInput') createUserInput: CreateUserInput) {
    return this.userClientService.register(createUserInput);
  }

  @Mutation('resetPassword')
  resetPasswored(
    @Args('resetPasswordUserInput')
    resetPasswordUserInput: ResetPasswordUserInput,
    @CurrentUser() user: IKeycloakAuthUser,
  ) {
    return this.userClientService.resetPassword(resetPasswordUserInput, user);
  }

  @Query('user')
  findOne(@Args('id') id: number) {
    return this.userClientService.findOne(id);
  }

  @Public()
  @Query('login')
  login(@Args('loginUserInput') loginUserInput: LoginUserInput) {
    return this.userClientService.login(loginUserInput);
  }

  @Public()
  @Query('accessTokenFromRefreshToken')
  userAccessTokenFromRefreshToken(@Args('refreshToken') refreshToken: string) {
    return this.userClientService.userAccessTokenFromRefreshToken(refreshToken);
  }

  @Mutation('updateUser')
  update(@Args('updateUserInput') updateUserInput: UpdateUserInput) {
    return this.userClientService.update(updateUserInput.id, updateUserInput);
  }

  @Query('logout')
  logout(@CurrentUser() user) {
    return this.userClientService.logout(user);
  }
}
