import { Test } from '@nestjs/testing';
import { AppModule } from './app.module';

/** Boot-level DI check: every controller/service dependency must resolve
 *  (catches "module forgot to import its dependency" drift — CI gate). */
describe('app module DI graph', () => {
  it('compiles the full module graph', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    expect(moduleRef.get(AppModule, { strict: false })).toBeDefined();
  });
});
