import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtService } from './jwt.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuditModule } from '../audit/audit.module';

/**
 * Auth module — global bearer gate lives here (APP_GUARD) so every controller
 * in the app is protected unless marked @Public() (C3/C6 foundation).
 */
@Module({
  imports: [AuditModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    // Factory: JwtService takes an optional plain-string test seam that Nest
    // cannot reflect-inject; production reads AUTH_JWT_SECRET from env.
    { provide: JwtService, useFactory: () => new JwtService() },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
  ],
  exports: [AuthService, JwtService],
})
export class AuthModule {}
