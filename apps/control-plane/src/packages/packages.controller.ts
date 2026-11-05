import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { PackagesService, PackageDto, CreatePackageInput } from './packages.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/**
 * Package lifecycle (API spec §4.5). `package:*` permissions are
 * Server-Admin-only for now (PermissionsGuard rejects non-super-admins
 * until reseller roles land); the decorators still name the permission so
 * the C6 coverage check and the API-token scope vocabulary stay exact.
 */
@Controller('packages')
export class PackagesController {
  constructor(private readonly packages: PackagesService) {}

  @Get()
  @RequirePermission('package:list')
  async list(): Promise<{ data: PackageDto[] }> {
    return this.packages.list();
  }

  @Get(':id')
  @RequirePermission('package:read')
  async get(@Param('id') id: string): Promise<PackageDto> {
    return this.packages.get(id);
  }

  @Post()
  @RequirePermission('package:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: CreatePackageInput,
  ): Promise<PackageDto> {
    return this.packages.create(body, user.userId);
  }

  @Patch(':id')
  @RequirePermission('package:update')
  async update(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: CreatePackageInput,
  ): Promise<PackageDto> {
    return this.packages.update(id, body, user.userId);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('package:delete')
  async remove(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.packages.remove(id, user.userId);
  }
}
