import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

/** Auth endpoints (API spec §4.1). M0 implements login only; 2FA lands in P2 (C2). */
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('login')
  @HttpCode(200)
  async login(
    @Body() body: { email?: string; password?: string; totp?: string },
  ): Promise<unknown> {
    return this.auth.login(body.email ?? '', body.password ?? '', body.totp);
  }
}
