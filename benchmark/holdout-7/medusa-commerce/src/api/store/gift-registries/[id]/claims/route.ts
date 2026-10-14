import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  GiftRegistry,
  MARKETPLACE_MANAGER,
  RegistryClaim,
} from "../../../../../modules/marketplace/models"

const MAX_CLAIM_QUANTITY = 12

type CreateClaimBody = {
  variant_id?: string
  quantity?: number
  claimed_by_email?: string
  gift_message?: string
}

const serialiseClaim = (claim: RegistryClaim) => ({
  id: claim.id,
  variant_id: claim.variant_id,
  quantity: claim.quantity,
  claimed_by_email: claim.claimed_by_email,
  gift_message: claim.gift_message,
  is_fulfilled: claim.is_fulfilled,
  created_at: claim.created_at,
})

/**
 * Loads the registry the caller owns, in the sales channel the publishable key
 * is scoped to. Returns null when either does not line up so callers can answer
 * 404 without leaking whether the id exists.
 */
const loadOwnedRegistry = async (
  em: EntityManager,
  req: MedusaRequest
): Promise<GiftRegistry | null> => {
  const customerId = req.auth_context?.actor_id
  if (!customerId || req.auth_context?.actor_type !== "customer") {
    return null
  }

  const channelIds = req.publishable_key_context?.sales_channel_ids ?? []

  return em.findOne(GiftRegistry, {
    id: req.params.id,
    customer_id: customerId,
    ...(channelIds.length ? { sales_channel_id: { $in: channelIds } } : {}),
  })
}

/**
 * The owner's view of who has claimed what, including the guest email so the
 * owner can chase a claim that never turned into an order.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const registry = await loadOwnedRegistry(em, req)
  if (!registry) {
    return res.status(404).json({ message: "Gift registry not found" })
  }

  const claims = await em.find(
    RegistryClaim,
    { registry: registry.id },
    { orderBy: { created_at: "ASC" } }
  )

  res.json({
    registry_id: registry.id,
    claims: claims.map(serialiseClaim),
    count: claims.length,
  })
}

/**
 * The owner reserving a line for themselves — used by the "I'll buy this one"
 * button on their own registry.
 */
export const POST = async (
  req: MedusaRequest<CreateClaimBody>,
  res: MedusaResponse
) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const registry = await loadOwnedRegistry(em, req)
  if (!registry) {
    return res.status(404).json({ message: "Gift registry not found" })
  }

  const body = (req.body ?? {}) as CreateClaimBody
  if (!body.variant_id) {
    return res.status(400).json({ message: "variant_id is required" })
  }

  const quantity = Number(body.quantity ?? 1)
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_CLAIM_QUANTITY) {
    return res
      .status(400)
      .json({ message: `quantity must be between 1 and ${MAX_CLAIM_QUANTITY}` })
  }

  const claim = em.create(RegistryClaim, {
    registry: em.getReference(GiftRegistry, registry.id),
    variant_id: body.variant_id,
    quantity,
    claimed_by_email: body.claimed_by_email ?? null,
    gift_message: body.gift_message ?? null,
    is_fulfilled: false,
  })

  await em.persistAndFlush(claim)

  res.status(201).json({ claim: serialiseClaim(claim) })
}
