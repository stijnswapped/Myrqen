import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import type { RegistryPreferencesInput } from "../../../../middlewares"
import {
  GiftRegistry,
  MARKETPLACE_MANAGER,
} from "../../../../../modules/marketplace/models"

const preferencesView = (registry: GiftRegistry) => ({
  id: registry.id,
  visibility: registry.visibility,
  event_date: registry.event_date,
  recipient_email: registry.recipient_email,
  updated_at: registry.updated_at,
})

/**
 * The small "sharing and reminders" panel, saved on change rather than behind a
 * save button, which is why it is its own endpoint.
 */
export const POST = async (
  req: MedusaRequest<RegistryPreferencesInput>,
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

  const input = req.validatedBody

  if (input.visibility === "public" && !registry.is_verified) {
    return res
      .status(409)
      .json({ message: "Public registries have to be verified by support first" })
  }

  em.assign(registry, {
    visibility: input.visibility ?? registry.visibility,
    event_date: input.event_date ? new Date(input.event_date) : registry.event_date,
    recipient_email: input.recipient_email ?? registry.recipient_email,
  })

  await em.persistAndFlush(registry)

  res.json({ gift_registry: preferencesView(registry) })
}
