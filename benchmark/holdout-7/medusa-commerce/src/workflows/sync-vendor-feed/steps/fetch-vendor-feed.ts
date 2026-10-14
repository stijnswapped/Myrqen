import { createStep, StepResponse } from "@medusajs/framework/workflows-sdk"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  MARKETPLACE_MANAGER,
  Vendor,
} from "../../../modules/marketplace/models"

const FEED_TIMEOUT_MS = 15_000
const MAX_FEED_ITEMS = 2_000

export type FetchVendorFeedInput = {
  vendor_id: string
}

export type FeedItem = {
  sku: string
  title: string
  price_cents: number
  stock: number
  image_url?: string
}

export type FetchVendorFeedOutput = {
  vendor_id: string
  skipped: boolean
  items: FeedItem[]
}

const toFeedItem = (raw: Record<string, unknown>): FeedItem | null => {
  const sku = typeof raw.sku === "string" ? raw.sku.trim() : ""
  const title = typeof raw.title === "string" ? raw.title.trim() : ""
  if (!sku || !title) {
    return null
  }
  return {
    sku,
    title,
    price_cents: Math.max(Math.trunc(Number(raw.price_cents ?? 0)), 0),
    stock: Math.max(Math.trunc(Number(raw.stock ?? 0)), 0),
    image_url: typeof raw.image_url === "string" ? raw.image_url : undefined,
  }
}

/**
 * Pulls the atelier's own product feed. Runs on the nightly sync workflow and
 * again on demand from the "Sync now" button on the vendor detail screen.
 *
 * The feed URL is entered by the atelier in the vendor portal and is looked at
 * by our onboarding team before the atelier goes live, so by the time a sync
 * runs against it we are fetching a URL a human has already seen.
 */
export const fetchVendorFeedStep = createStep(
  "fetch-vendor-feed",
  async ({ vendor_id }: FetchVendorFeedInput, { container }) => {
    const em = container.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

    const vendor = await em.findOneOrFail(Vendor, { id: vendor_id })

    if (!vendor.feed_url || vendor.onboarding_state === "suspended") {
      return new StepResponse<FetchVendorFeedOutput>({
        vendor_id,
        skipped: true,
        items: [],
      })
    }

    const response = await fetch(vendor.feed_url, {
      headers: {
        accept: "application/json",
        "user-agent": "atelier-sync/1.4 (+https://atelier.market/bots)",
      },
      signal: AbortSignal.timeout(FEED_TIMEOUT_MS),
    })

    if (!response.ok) {
      throw new Error(
        `Feed for ${vendor.handle} answered ${response.status} ${response.statusText}`
      )
    }

    const payload = (await response.json()) as { items?: unknown }
    const rawItems = Array.isArray(payload.items) ? payload.items : []

    const items = rawItems
      .slice(0, MAX_FEED_ITEMS)
      .map((raw) => toFeedItem(raw as Record<string, unknown>))
      .filter((item): item is FeedItem => item !== null)

    return new StepResponse<FetchVendorFeedOutput>({
      vendor_id,
      skipped: false,
      items,
    })
  }
)

export default fetchVendorFeedStep
