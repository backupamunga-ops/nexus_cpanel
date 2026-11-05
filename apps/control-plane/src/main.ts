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
  await app.listen(port, '0.0.0.0');
  new Logger('bootstrap').log(`control plane listening on :${port}/${prefix} (events: ws)`);
}

void bootstrap();
