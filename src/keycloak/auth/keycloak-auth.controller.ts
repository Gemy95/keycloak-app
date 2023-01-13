import {
  Headers,
  Controller,
  Get,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  All,
  Body,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth } from '@nestjs/swagger';
import { Public } from 'nest-keycloak-connect';
import { KeycloakAuthService } from './keycloak-auth.service';
@Controller('keycloak')
export class KeycloakController {
  constructor(private keyCloakService: KeycloakAuthService) {}

  @Get('')
  @UseGuards(AuthGuard('keycloak'))
  async login(@Req() req) {}

  @Get('loginCallback')
  @UseGuards(AuthGuard('keycloak'))
  async loginCallback(@Req() req, @Res() res) {
    res.redirect('');
  }

  @Get('/admin/token')
  @Public()
  async admin() {
    return this.keyCloakService.getAdminAccessToken();
  }
}
