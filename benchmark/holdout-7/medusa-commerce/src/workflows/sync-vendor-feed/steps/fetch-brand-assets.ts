import { createStep, StepResponse } from "@medusajs/framework/workflows-sdk"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  MARKETPLACE_MANAGER,
  Vendor,
} from "../../../modules/marketplace/models"

const ASSET_TIMEOUT_MS = 10_000
const MAX_ASSET_BYTES = 5 * 1024 * 1024

/**
 * Image origins ateliers are asked to publish their brand assets on during
 * onboarding. Anything else has to be uploaded through the dashboard instead.
 */
const ALLOWED_ASSET_HOSTS = new Set([
  "cdn.atelier.market",
  "assets.atelier.market",
  "images.ctfassets.net",
  "res.cloudinary.com",
])

export type FetchBrandAssetsInput = {
  vendor_id: string
  /** Relative path inside the atelier's asset base, e.g. "logo-dark.svg". */
  asset_path: string
}

export type FetchBrandAssetsOutput = {
  vendor_id: string
  skipped: boolean
  content_type: string | null
  byte_length: number
}

/**
 * Resolves the atelier's asset_base_url against one relative path and returns
 * the URL only when it lands on an origin we publish assets from. Returning null
 * makes the step skip rather than fail, because a missing logo should not hold up
 * a catalogue sync.
 */
const resolveAssetUrl = (baseUrl: string, assetPath: string): URL | null => {
  let url: URL
  try {
    url = new URL(assetPath, baseUrl)
  } catch {
    return null
  }

  if (url.protocol !== "https:") {
    return null
  }
  if (!ALLOWED_ASSET_HOSTS.has(url.hostname)) {
    return null
  }
  if (url.port && url.port !== "443") {
    return null
  }

  return url
}

/**
 * Mirrors one brand asset off the atelier's CDN so the storefront never links
 * straight at a third party origin.
 */
export const fetchBrandAssetsStep = createStep(
  "fetch-brand-assets",
  async (
    { vendor_id, asset_path }: FetchBrandAssetsInput,
    { container }
  ) => {
    const em = container.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

    const vendor = await em.findOneOrFail(Vendor, { id: vendor_id })

    const assetUrl = vendor.asset_base_url
      ? resolveAssetUrl(vendor.asset_base_url, asset_path)
      : null

    if (!assetUrl) {
      return new StepResponse<FetchBrandAssetsOutput>({
        vendor_id,
        skipped: true,
        content_type: null,
        byte_length: 0,
      })
    }

    const response = await fetch(assetUrl, {
      headers: { accept: "image/*" },
      redirect: "error",
      signal: AbortSignal.timeout(ASSET_TIMEOUT_MS),
    })

    if (!response.ok) {
      throw new Error(
        `Asset ${asset_path} for ${vendor.handle} answered ${response.status}`
      )
    }

    const body = await response.arrayBuffer()
    if (body.byteLength > MAX_ASSET_BYTES) {
      throw new Error(`Asset ${asset_path} for ${vendor.handle} is too large`)
    }

    return new StepResponse<FetchBrandAssetsOutput>({
      vendor_id,
      skipped: false,
      content_type: response.headers.get("content-type"),
      byte_length: body.byteLength,
    })
  }
)

export default fetchBrandAssetsStep
