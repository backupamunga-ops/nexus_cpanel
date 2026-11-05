import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtService } from './jwt.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard } from './permissions.guard';
import { ApiTokensService } from './api-tokens.service';
import { TokensController } from './api-tokens.controller';
import { AuditModule } from '../audit/audit.module';

/**
 * Auth module — global gates live here (APP_GUARD) so every controller in
 * the app is authenticated (JwtAuthGuard: session JWTs AND API tokens, C3/C4)
 * and authorized (PermissionsGuard, C6) unless marked @Public(). Guard ORDER
 * matters: authentication first.
 */
@Module({
  imports: [AuditModule],
  controllers: [AuthController, TokensController],
  providers: [
    AuthService,
    ApiTokensService,
    // Factory: JwtService takes an optional plain-string test seam that Nest
    // cannot reflect-inject; production reads AUTH_JWT_SECRET from env.
    { provide: JwtService, useFactory: () => new JwtService() },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
  ],
  exports: [AuthService, JwtService, ApiTokensService],
})
export class AuthModule {}
