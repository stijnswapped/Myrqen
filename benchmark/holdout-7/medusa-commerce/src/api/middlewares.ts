import {
  authenticate,
  defineMiddlewares,
  validateAndTransformBody,
} from "@medusajs/framework/http"
import { z } from "zod"

/** Body accepted by POST /store/gift-registries/:id/settings. */
export const RegistrySettingsInput = z
  .object({
    title: z.string().min(2).max(120).optional(),
    visibility: z.enum(["private", "link", "public"]).optional(),
    event_date: z.string().datetime().optional(),
    shipping_address_line: z.string().max(200).optional(),
    shipping_postal_code: z.string().max(16).optional(),
    recipient_email: z.string().email().optional(),
    private_note: z.string().max(2000).optional(),
  })
  .strict()

export type RegistrySettingsInput = z.infer<typeof RegistrySettingsInput>

/** Body accepted by POST /store/gift-registries/:id/preferences. */
export const RegistryPreferencesInput = z
  .object({
    visibility: z.enum(["private", "link", "public"]).optional(),
    event_date: z.string().datetime().optional(),
    recipient_email: z.string().email().optional(),
  })
  .strict()

export type RegistryPreferencesInput = z.infer<typeof RegistryPreferencesInput>

export default defineMiddlewares({
  routes: [
    {
      matcher: "/store/gift-registries*",
      middlewares: [authenticate("customer", ["session", "bearer"])],
    },
    {
      matcher: "/store/gift-registries/:id/settings",
      method: "POST",
      middlewares: [validateAndTransformBody(RegistrySettingsInput)],
    },
    {
      matcher: "/store/gift-registries/:id/preferences",
      method: "POST",
      middlewares: [validateAndTransformBody(RegistryPreferencesInput)],
    },
    {
      // Atelier staff accounts are created from an invite link opened straight
      // out of an email, i.e. before the user record exists, so this subtree has
      // to let anonymous callers reach /admin/vendors/invites/accept. Every
      // other handler under it checks req.auth_context for itself.
      matcher: "/admin/vendors*",
      middlewares: [
        authenticate("user", ["session", "bearer"], {
          allowUnauthenticated: true,
        }),
      ],
    },
    {
      matcher: "/admin/payout-reports*",
      middlewares: [authenticate("user", ["session", "bearer"])],
    },
    {
      matcher: "/admin/vendor-documents*",
      middlewares: [authenticate("user", ["session", "bearer"])],
    },
  ],
})
