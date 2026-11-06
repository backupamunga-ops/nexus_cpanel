/**
 * NexusPanel control-plane bootstrap.
 *
 * The control plane NEVER runs as root and never touches the system directly:
 * every privileged operation is a signed command to the Go agent
 * (specs/nexuspanel-agent-spec-v1.0.md).
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { WsAdapter } from '@nestjs/platform-ws';
import { AppModule } from './app.module';
import { ProblemDetailsFilter } from './common/problem-details.filter';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const prefix = process.env.GLOBAL_PREFIX || 'api/v1';
  app.setGlobalPrefix(prefix);
  // WebSocket gateways speak raw ws protocol (not socket.io).
  app.useWebSocketAdapter(new WsAdapter(app));
  app.useGlobalFilters(new ProblemDetailsFilter());
  app.useGlobalPipes(
    new ValidationPipe({ transform: true, whitelist: true }),
  );
  const port = Number(process.env.PORT || 3000);
  // Bind loopback in production (the public origin proxies to 127.0.0.1) —
  // finding #11 of the live-VM run: the unit shipped without HOST and the API
  // answered on 0.0.0.0, relying on ufw alone. Dev rigs (no HOST set) keep the
  // historic all-interfaces behavior so compose/LAN setups don't break.
  const host = process.env.HOST || '0.0.0.0';
  await app.listen(port, host);
  new Logger('bootstrap').log(`control plane listening on ${host}:${port}/${prefix} (events: ws)`);
}

void bootstrap();
