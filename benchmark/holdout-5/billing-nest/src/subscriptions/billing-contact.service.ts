import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, Repository } from 'typeorm';
import { Subscription } from '../billing/entities/subscription.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';
import type { BillingContactDto } from './dto/billing-contact.dto';

export interface BillingContactView {
  subscriptionId: string;
  billingContactName: string;
  billingContactEmail: string;
  purchaseOrderReference: string | null;
}

@Injectable()
export class BillingContactService {
  private readonly logger = new Logger(BillingContactService.name);

  constructor(
    @InjectRepository(Subscription)
    private readonly subscriptions: Repository<Subscription>,
  ) {}

  /**
   * Who receives the invoices, and under which PO number. Reached from
   * PATCH /api/subscriptions/:subscriptionId/billing-contact.
   */
  async updateContact(
    subscriptionId: string,
    patch: BillingContactDto,
    actor: AuthenticatedUser,
  ): Promise<BillingContactView> {
    const subscription = await this.subscriptions.findOne({
      where: { id: subscriptionId, organisationId: actor.organisationId },
    });

    if (!subscription) {
      throw new NotFoundException(`Subscription ${subscriptionId} does not exist`);
    }

    // Only the three contact columns are writable here. Anything else the
    // client sends along is dropped on the floor because it never makes it
    // into the object handed to merge().
    const writable: DeepPartial<Subscription> = {
      billingContactName: patch.billingContactName,
      billingContactEmail: patch.billingContactEmail.toLowerCase(),
      purchaseOrderReference: patch.purchaseOrderReference ?? null,
      updatedById: actor.id,
    };

    const updated = this.subscriptions.merge(subscription, writable);

    await this.subscriptions.save(updated);

    this.logger.log(
      `billing contact for subscription ${updated.id} changed by ${actor.email}`,
    );

    return {
      subscriptionId: updated.id,
      billingContactName: updated.billingContactName,
      billingContactEmail: updated.billingContactEmail,
      purchaseOrderReference: updated.purchaseOrderReference,
    };
  }
}
