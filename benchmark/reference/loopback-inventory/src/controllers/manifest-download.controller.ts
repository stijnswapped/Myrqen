import path from 'node:path';
import {createReadStream} from 'node:fs';
import {stat} from 'node:fs/promises';
import {get, param, HttpErrors, type Response, RestBindings} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {companyOf, type WarehouseUser} from '../lib/tenancy';

const MANIFEST_ROOT = '/srv/warehouse/manifests';

/** A stored manifest name: one path segment, no separators, no parent hop. */
const MANIFEST_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.pdf$/;

/**
 * Shipping manifests, stored the same way as labels.
 */
@authenticate('jwt')
export class ManifestDownloadController {
  constructor(
    @inject(RestBindings.Http.RESPONSE) private response: Response,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Stream a manifest PDF.
   *
   * The name must match a pattern admitting a single path segment, and `..` is refused
   * explicitly because the character class allows a dot. Both checks run before the join, so
   * nothing reaching `path.join` can climb out of the company's directory.
   */
  @get('/manifests/{name}')
  async download(@param.path.string('name') name: string): Promise<Response> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    if (!MANIFEST_NAME.test(name) || name.includes('..')) {
      throw new HttpErrors.BadRequest('That is not a valid manifest name.');
    }
    const absolute = path.join(MANIFEST_ROOT, companyId, name);
    const info = await stat(absolute).catch(() => null);
    if (!info?.isFile()) {
      throw new HttpErrors.NotFound('That manifest is no longer stored.');
    }
    this.response.setHeader('Content-Type', 'application/pdf');
    createReadStream(absolute).pipe(this.response);
    return this.response;
  }
}
