import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  CurrentUser,
  JwtAuthGuard,
  type AuthenticatedUser,
} from '../auth/jwt-auth.guard';
import { Roles } from '../auth/roles.guard';
import { AdjustmentsService, type AdjustmentView } from './adjustments.service';
import { CreateAdjustmentDto } from './dto/create-adjustment.dto';

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

/**
 * Manual ledger corrections. Finance books one of these when a payment
 * provider settles a different amount than the invoice was issued for, or
 * when a duplicate charge has to be reversed by hand.
 */
@Controller('api/adjustments')
@UseGuards(JwtAuthGuard)
export class AdjustmentsController {
  constructor(private readonly adjustments: AdjustmentsService) {}

  /** Corrections booked against the caller's own organisation, newest first. */
  @Get()
  async list(
    @CurrentUser() actor: AuthenticatedUser,
    @Query('limit') limit?: string,
  ): Promise<AdjustmentView[]> {
    const parsed = Number.parseInt(limit ?? '', 10);
    const take = Math.min(Number.isNaN(parsed) ? DEFAULT_PAGE_SIZE : parsed, MAX_PAGE_SIZE);

    return this.adjustments.listForOrganisation(actor.organisationId, take);
  }

  /**
   * Book a correction against an invoice. This one is finance-only: the @Roles
   * metadata below pins the handler to billing_admin, so an operator or viewer
   * token is turned away before the body is even read.
   */
  @Post()
  @Roles('billing_admin')
  @HttpCode(201)
  async create(
    @Body() body: CreateAdjustmentDto,
    @CurrentUser() actor: AuthenticatedUser,
  ): Promise<AdjustmentView> {
    return this.adjustments.record({
      organisationId: actor.organisationId,
      invoiceId: body.invoiceId,
      amountCents: body.amountCents,
      memo: body.memo,
      createdById: actor.id,
    });
  }
}
