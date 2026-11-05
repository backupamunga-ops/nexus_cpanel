import { Module } from '@nestjs/common';
import { SshKeysController } from './sshkeys.controller';
import { SshKeysService } from './sshkeys.service';

@Module({
  controllers: [SshKeysController],
  providers: [SshKeysService],
  exports: [SshKeysService],
})
export class SshKeysModule {}
