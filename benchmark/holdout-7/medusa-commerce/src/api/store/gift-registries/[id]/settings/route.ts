import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import type { RegistrySettingsInput } from "../../../../middlewares"
import {
  GiftRegistry,
  MARKETPLACE_MANAGER,
} from "../../../../../modules/marketplace/models"

const settingsView = (registry: GiftRegistry) => ({
  id: registry.id,
  title: registry.title,
  event_date: registry.event_date,
  visibility: registry.visibility,
  shipping_address_line: registry.shipping_address_line,
  shipping_postal_code: registry.shipping_postal_code,
  recipient_email: registry.recipient_email,
  private_note: registry.private_note,
  updated_at: registry.updated_at,
})

/**
 * The "Registry settings" form in the storefront account area. One form, one
 * save button, so the handler takes the whole form payload in one go.
 */
export const POST = async (
  req: MedusaRequest<RegistrySettingsInput>,
  res: MedusaResponse
) => {
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

  if (registry.visibility === "public" && !registry.is_verified) {
    return res
      .status(409)
      .json({ message: "Public registries have to be verified by support first" })
  }

  // validateAndTransformBody(RegistrySettingsInput) has already rejected the
  // request if any field is the wrong shape, and assign() only writes the
  // properties the schema declares, so anything else in the payload is dropped
  // on the floor.
  em.assign(registry, req.body)

  await em.persistAndFlush(registry)

  res.json({ gift_registry: settingsView(registry) })
}

export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
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

  res.json({ gift_registry: settingsView(registry) })
}
