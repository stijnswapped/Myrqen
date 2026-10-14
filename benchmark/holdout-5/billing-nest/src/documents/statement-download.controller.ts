import {
  Controller,
  Get,
  Header,
  Logger,
  NotFoundException,
  Param,
  StreamableFile,
  UseGuards,
} from '@nestjs/common';
import { createReadStream, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  CurrentUser,
  JwtAuthGuard,
  type AuthenticatedUser,
} from '../auth/jwt-auth.guard';
import { BillingConfigService } from '../config/billing-config.service';
import { StatementIndexService } from './statement-index.service';

/**
 * Monthly account statements, streamed straight off the shared documents
 * volume. The renderer writes them there as part of the month end job.
 */
@Controller('api/documents')
@UseGuards(JwtAuthGuard)
export class StatementDownloadController {
  private readonly logger = new Logger(StatementDownloadController.name);

  constructor(
    private readonly config: BillingConfigService,
    private readonly index: StatementIndexService,
  ) {}

  @Get('statements/:reference')
  @Header('Content-Type', 'application/pdf')
  @Header('Cache-Control', 'private, no-store')
  async download(
    @Param('reference') reference: string,
    @CurrentUser() actor: AuthenticatedUser,
  ): Promise<StreamableFile> {
    const indexed = await this.index.findForOrganisation(
      reference,
      actor.organisationId,
    );

    if (indexed) {
      const current = join(this.config.statementRoot, indexed.storedFileName);
      this.logger.log(`statement ${indexed.reference} served to ${actor.email}`);

      return new StreamableFile(createReadStream(current));
    }

    // Statements printed before the 2024 archive migration were never indexed.
    // They still sit on the archive volume under the reference finance quotes
    // in the original e-mail, so we address the file directly. The reference
    // arrives as a single URL path segment, which means Express has already
    // split it on the slashes for us and it cannot name anything outside this
    // one directory.
    const archived = join(this.config.statementArchiveRoot, `${reference}.pdf`);

    if (!existsSync(archived)) {
      throw new NotFoundException(`No statement ${reference} on file`);
    }

    this.logger.log(`archived statement ${reference} served to ${actor.email}`);

    return new StreamableFile(createReadStream(archived));
  }
}
