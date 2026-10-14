import {
  BadRequestException,
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
import { join, resolve, sep } from 'node:path';
import {
  CurrentUser,
  JwtAuthGuard,
  type AuthenticatedUser,
} from '../auth/jwt-auth.guard';
import { BillingConfigService } from '../config/billing-config.service';
import { CreditNoteIndexService } from './credit-note-index.service';

/** Credit notes are numbered CN-<year>-<sequence>, e.g. CN-2026-000418. */
const CREDIT_NOTE_REFERENCE = /^CN-\d{4}-\d{6}$/;

@Controller('api/documents')
@UseGuards(JwtAuthGuard)
export class CreditNoteDownloadController {
  private readonly logger = new Logger(CreditNoteDownloadController.name);

  constructor(
    private readonly config: BillingConfigService,
    private readonly index: CreditNoteIndexService,
  ) {}

  @Get('credit-notes/:reference')
  @Header('Content-Type', 'application/pdf')
  @Header('Cache-Control', 'private, no-store')
  async download(
    @Param('reference') reference: string,
    @CurrentUser() actor: AuthenticatedUser,
  ): Promise<StreamableFile> {
    if (!CREDIT_NOTE_REFERENCE.test(reference)) {
      throw new BadRequestException('Malformed credit note reference');
    }

    const indexed = await this.index.findForOrganisation(
      reference,
      actor.organisationId,
    );

    if (indexed) {
      const current = join(this.config.creditNoteRoot, indexed.storedFileName);
      this.logger.log(`credit note ${indexed.reference} served to ${actor.email}`);

      return new StreamableFile(createReadStream(current));
    }

    // Pre-migration credit notes were never indexed and are addressed by their
    // reference on the archive volume. The reference has already been matched
    // against the numbering pattern above, and we re-check that the resolved
    // file still sits under the archive root before opening it.
    const root = resolve(this.config.creditNoteArchiveRoot);
    const archived = resolve(root, `${reference}.pdf`);

    if (!archived.startsWith(`${root}${sep}`)) {
      throw new BadRequestException('Credit note reference is out of range');
    }

    if (!existsSync(archived)) {
      throw new NotFoundException(`No credit note ${reference} on file`);
    }

    this.logger.log(`archived credit note ${reference} served to ${actor.email}`);

    return new StreamableFile(createReadStream(archived));
  }
}
