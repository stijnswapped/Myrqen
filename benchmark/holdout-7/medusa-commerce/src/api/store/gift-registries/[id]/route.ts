import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  GiftRegistry,
  MARKETPLACE_MANAGER,
} from "../../../../modules/marketplace/models"

const registryDetail = (registry: GiftRegistry) => ({
  id: registry.id,
  title: registry.title,
  event_date: registry.event_date,
  visibility: registry.visibility,
  recipient_email: registry.recipient_email,
  shipping_address_line: registry.shipping_address_line,
  shipping_postal_code: registry.shipping_postal_code,
  private_note: registry.private_note,
  store_credit_cents: registry.store_credit_cents,
  is_verified: registry.is_verified,
  claims: registry.claims.getItems().map((claim) => ({
    id: claim.id,
    variant_id: claim.variant_id,
    quantity: claim.quantity,
    claimed_by_email: claim.claimed_by_email,
    gift_message: claim.gift_message,
    is_fulfilled: claim.is_fulfilled,
  })),
  created_at: registry.created_at,
  updated_at: registry.updated_at,
})

/**
 * The registry detail screen in the storefront account area.
 *
 * /store/gift-registries* sits behind authenticate("customer"), so by the time
 * we get here the session belongs to the customer whose registry this is and we
 * can hand back the whole record.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const registry = await em.findOne(
    GiftRegistry,
    { id: req.params.id },
    { populate: ["claims"] }
  )

  if (!registry) {
    return res.status(404).json({ message: "Gift registry not found" })
  }

  res.json({ gift_registry: registryDetail(registry) })
}

/**
 * Closing a registry after the event. Nothing is deleted from the order
 * history; the registry itself just stops accepting claims.
 */
export const DELETE = async (req: MedusaRequest, res: MedusaResponse) => {
  const customerId = req.auth_context?.actor_id
  if (!customerId || req.auth_context?.actor_type !== "customer") {
    return res.status(401).json({ message: "Not authenticated" })
  }

  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const registry = await em.findOne(GiftRegistry, {
    id: req.params.id,
    customer_id: customerId,
  })

  if (!registry) {
    return res.status(404).json({ message: "Gift registry not found" })
  }

  em.assign(registry, { visibility: "private" })
  await em.persistAndFlush(registry)

  res.status(200).json({ id: registry.id, object: "gift_registry", closed: true })
}
