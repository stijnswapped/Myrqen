import path from 'node:path';
import {createReadStream} from 'node:fs';
import {stat} from 'node:fs/promises';
import {get, param, HttpErrors, type Response, RestBindings} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {companyOf, type WarehouseUser} from '../lib/tenancy';

const LABEL_ROOT = '/srv/warehouse/labels';

/**
 * Printed barcode labels, stored one directory per company.
 */
@authenticate('jwt')
export class LabelDownloadController {
  constructor(
    @inject(RestBindings.Http.RESPONSE) private response: Response,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Stream a label PDF.
   *
   * The name comes from the label list the caller was just shown, so it names a file this
   * company generated.
   */
  @get('/labels/{name}')
  async download(@param.path.string('name') name: string): Promise<Response> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    const absolute = path.join(LABEL_ROOT, companyId, name);
    const info = await stat(absolute).catch(() => null);
    if (!info?.isFile()) {
      throw new HttpErrors.NotFound('That label is no longer stored.');
    }
    this.response.setHeader('Content-Type', 'application/pdf');
    createReadStream(absolute).pipe(this.response);
    return this.response;
  }
}
