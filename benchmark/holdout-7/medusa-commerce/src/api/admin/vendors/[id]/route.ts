import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  MARKETPLACE_MANAGER,
  Vendor,
  VendorMember,
} from "../../../../modules/marketplace/models"

type UpdateVendorBody = {
  display_name?: string
  feed_url?: string | null
  asset_base_url?: string | null
  payout_iban_last4?: string
}

const serialiseVendor = (vendor: Vendor) => ({
  id: vendor.id,
  handle: vendor.handle,
  display_name: vendor.display_name,
  feed_url: vendor.feed_url,
  asset_base_url: vendor.asset_base_url,
  sales_channel_id: vendor.sales_channel_id,
  commission_bps: vendor.commission_bps,
  is_payout_enabled: vendor.is_payout_enabled,
  onboarding_state: vendor.onboarding_state,
  created_at: vendor.created_at,
  updated_at: vendor.updated_at,
})

/**
 * /admin/vendors* runs the authenticate middleware with allowUnauthenticated so
 * that the invite-acceptance endpoint can be reached from an email link, which
 * means every other handler in the subtree has to establish the actor itself.
 */
const requireStaffActor = (req: MedusaRequest): string | null => {
  if (req.auth_context?.actor_type !== "user") {
    return null
  }
  return req.auth_context.actor_id || null
}

export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const actorId = requireStaffActor(req)
  if (!actorId) {
    return res.status(401).json({ message: "Not authenticated" })
  }

  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const vendor = await em.findOne(Vendor, { id: req.params.id })
  if (!vendor) {
    return res.status(404).json({ message: "Atelier not found" })
  }

  const members = await em.find(VendorMember, { vendor: vendor.id })

  res.json({
    vendor: serialiseVendor(vendor),
    members: members.map((member) => ({
      id: member.id,
      user_id: member.user_id,
      role: member.role,
    })),
  })
}

/**
 * Updates the atelier's public profile. Only the four fields the dashboard form
 * actually renders are copied across; the payout flags and the commission rate
 * are moved by the finance tooling, not from here.
 */
export const POST = async (
  req: MedusaRequest<UpdateVendorBody>,
  res: MedusaResponse
) => {
  const actorId = requireStaffActor(req)
  if (!actorId) {
    return res.status(401).json({ message: "Not authenticated" })
  }

  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const vendor = await em.findOne(Vendor, { id: req.params.id })
  if (!vendor) {
    return res.status(404).json({ message: "Atelier not found" })
  }

  const body = (req.body ?? {}) as UpdateVendorBody

  if (typeof body.feed_url === "string" && body.feed_url.length > 0) {
    let parsed: URL
    try {
      parsed = new URL(body.feed_url)
    } catch {
      return res.status(400).json({ message: "feed_url must be an absolute URL" })
    }
    if (parsed.protocol !== "https:") {
      return res.status(400).json({ message: "feed_url must use https" })
    }
  }

  em.assign(vendor, {
    display_name: body.display_name ?? vendor.display_name,
    feed_url: body.feed_url === undefined ? vendor.feed_url : body.feed_url,
    asset_base_url:
      body.asset_base_url === undefined
        ? vendor.asset_base_url
        : body.asset_base_url,
    payout_iban_last4: body.payout_iban_last4 ?? vendor.payout_iban_last4,
  })

  await em.persistAndFlush(vendor)

  res.json({ vendor: serialiseVendor(vendor) })
}
