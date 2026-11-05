import { SetMetadata } from '@nestjs/common';

/**
 * Marks an endpoint as unauthenticated (health, auth/login, auth/refresh).
 * Everything else requires a valid access token via the global JwtAuthGuard.
 */
export const IS_PUBLIC_KEY = 'nexuspanel:isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
