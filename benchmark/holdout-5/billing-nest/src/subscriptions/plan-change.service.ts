import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, Repository } from 'typeorm';
import { Subscription } from '../billing/entities/subscription.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';
import type { PlanChangeDto } from './dto/plan-change.dto';

interface CataloguePlan {
  code: string;
  name: string;
  seatsIncluded: number;
  listPriceCents: number;
}

/** The published price list. Sales cannot deviate from it without a contract. */
const PLAN_CATALOGUE: Record<string, CataloguePlan> = {
  team_monthly: { code: 'team_monthly', name: 'Team', seatsIncluded: 10, listPriceCents: 29_00 },
  business_monthly: {
    code: 'business_monthly',
    name: 'Business',
    seatsIncluded: 50,
    listPriceCents: 79_00,
  },
  enterprise_annual: {
    code: 'enterprise_annual',
    name: 'Enterprise',
    seatsIncluded: 250,
    listPriceCents: 899_00,
  },
};

export interface PlanChangeReceipt {
  subscriptionId: string;
  planCode: string;
  seats: number;
  unitPriceCents: number;
  proratedChargeCents: number;
  effectiveFrom: string;
}

@Injectable()
export class PlanChangeService {
  private readonly logger = new Logger(PlanChangeService.name);

  constructor(
    @InjectRepository(Subscription)
    private readonly subscriptions: Repository<Subscription>,
  ) {}

  /**
   * Upgrade or downgrade a subscription. Reached from
   * PATCH /api/subscriptions/:subscriptionId/plan.
   */
  async applyPlanChange(
    subscriptionId: string,
    patch: PlanChangeDto,
    actor: AuthenticatedUser,
  ): Promise<PlanChangeReceipt> {
    const subscription = await this.subscriptions.findOne({
      where: { id: subscriptionId, organisationId: actor.organisationId },
    });

    if (!subscription) {
      throw new NotFoundException(`Subscription ${subscriptionId} does not exist`);
    }

    const plan = PLAN_CATALOGUE[patch.planCode];

    if (!plan) {
      throw new BadRequestException(`Unknown plan ${patch.planCode}`);
    }

    const seats = patch.seats ?? subscription.seats;

    if (seats > plan.seatsIncluded) {
      throw new BadRequestException(`${plan.name} covers at most ${plan.seatsIncluded} seats`);
    }

    // The payload has been through the global ValidationPipe on the way in, so
    // every field on `patch` is already the right type. That lets us hand the
    // whole body to the repository instead of copying two dozen columns across
    // by hand every time product adds one; plan code and price we pin to the
    // catalogue so nobody can talk themselves into a cheaper tier.
    const updated = this.subscriptions.merge(subscription, {
      ...patch,
      planCode: plan.code,
      unitPriceCents: plan.listPriceCents,
      seats,
      updatedById: actor.id,
    } as DeepPartial<Subscription>);

    const proratedChargeCents = prorate(updated, subscription);
    updated.effectiveFrom = today();

    await this.subscriptions.save(updated);

    this.logger.log(
      `subscription ${updated.id} moved to ${plan.code} by ${actor.email}`,
    );

    return {
      subscriptionId: updated.id,
      planCode: updated.planCode,
      seats: updated.seats,
      unitPriceCents: updated.unitPriceCents,
      proratedChargeCents,
      effectiveFrom: updated.effectiveFrom,
    };
  }
}

/** Charge for the remainder of the current period at the new rate. */
function prorate(next: Subscription, previous: Subscription): number {
  const daysLeft = Math.max(
    0,
    Math.ceil(
      (new Date(previous.currentPeriodEnd).getTime() - Date.now()) / 86_400_000,
    ),
  );
  const dailyDelta = (next.unitPriceCents - previous.unitPriceCents) / 30;
  const gross = Math.round(dailyDelta * daysLeft * next.seats);

  return Math.max(0, Math.round(gross * (1 - next.discountBps / 10_000)));
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}
