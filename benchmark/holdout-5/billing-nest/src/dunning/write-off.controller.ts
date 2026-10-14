import {
  Body,
  Controller,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  CurrentUser,
  JwtAuthGuard,
  type AuthenticatedUser,
} from '../auth/jwt-auth.guard';
import { Roles, RolesGuard } from '../auth/roles.guard';
import { CaseWriteOffService, type WriteOffReceipt } from './case-write-off.service';
import { WriteOffDto } from './dto/write-off.dto';

/**
 * Closing a dunning case as uncollectable moves money out of receivables, so
 * it is a finance-only action just like a ledger correction.
 */
@Controller('api/dunning')
@UseGuards(JwtAuthGuard, RolesGuard)
export class WriteOffController {
  constructor(private readonly writeOffs: CaseWriteOffService) {}

  @Post('cases/:caseId/write-off')
  @Roles('billing_admin')
  @HttpCode(201)
  async writeOff(
    @Param('caseId', ParseUUIDPipe) caseId: string,
    @Body() body: WriteOffDto,
    @CurrentUser() actor: AuthenticatedUser,
  ): Promise<WriteOffReceipt> {
    return this.writeOffs.close({
      caseId,
      organisationId: actor.organisationId,
      reasonCode: body.reasonCode,
      memo: body.memo,
      closedById: actor.id,
    });
  }
}
