import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { JwtService } from './jwt.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard } from './permissions.guard';
import { ApiTokensService } from './api-tokens.service';
import { TokensController } from './api-tokens.controller';
import { TwoFactorService } from './two-factor.service';
import { SecretBox } from './secret-box';
import { AuditModule } from '../audit/audit.module';
import { SettingsModule } from '../settings/settings.module';

/**
 * Auth module — global gates live here (APP_GUARD) so every controller in
 * the app is authenticated (JwtAuthGuard: session JWTs AND API tokens, C3/C4)
 * and authorized (PermissionsGuard, C6) unless marked @Public(). Guard ORDER
 * matters: authentication first.
 */
@Module({
  imports: [AuditModule, SettingsModule],
  controllers: [AuthController, TokensController],
  providers: [
    AuthService,
    ApiTokensService,
    TwoFactorService,
    PasswordService,
    // Factory: SecretBox takes an optional plain-Buffer test seam that Nest
    // cannot reflect-inject (a union with Buffer compiles to an `Object`
    // token); production resolves CP_SECRETS_KEY(_PATH) from env.
    { provide: SecretBox, useFactory: () => new SecretBox() },
    { provide: JwtService, useFactory: () => new JwtService() },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
  ],
  exports: [AuthService, JwtService, ApiTokensService, TwoFactorService, SecretBox],
})
export class AuthModule {}
