import { relations } from "drizzle-orm";
import { boolean, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

export const customers = pgTable("customers", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  displayName: text("display_name"),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
}, (table) => ({
  emailKey: uniqueIndex("customers_email_key").on(table.email)
}));

export const staff = pgTable("staff", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  role: text("role").notNull(),
  disabledAt: timestamp("disabled_at", { withTimezone: true })
}, (table) => ({
  emailKey: uniqueIndex("staff_email_key").on(table.email)
}));

export const products = pgTable("products", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull().default(""),
  status: text("status").notNull().default("draft"),
  heroImage: text("hero_image"),
  publishedAt: timestamp("published_at", { withTimezone: true })
}, (table) => ({
  slugKey: uniqueIndex("products_slug_key").on(table.slug)
}));

export const variants = pgTable("variants", {
  id: uuid("id").primaryKey().defaultRandom(),
  productId: uuid("product_id").notNull().references(() => products.id),
  sku: text("sku").notNull(),
  optionLabel: text("option_label").notNull(),
  priceCents: integer("price_cents").notNull(),
  compareAtCents: integer("compare_at_cents"),
  inventoryOnHand: integer("inventory_on_hand").notNull().default(0),
  active: boolean("active").notNull().default(true)
}, (table) => ({
  skuKey: uniqueIndex("variants_sku_key").on(table.sku),
  byProduct: index("variants_product_idx").on(table.productId)
}));

export const carts = pgTable("carts", {
  id: uuid("id").primaryKey().defaultRandom(),
  customerId: uuid("customer_id").references(() => customers.id),
  token: text("token").notNull(),
  currency: text("currency").notNull().default("EUR"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
}, (table) => ({
  tokenKey: uniqueIndex("carts_token_key").on(table.token)
}));

export const cartLines = pgTable("cart_lines", {
  id: uuid("id").primaryKey().defaultRandom(),
  cartId: uuid("cart_id").notNull().references(() => carts.id),
  variantId: uuid("variant_id").notNull().references(() => variants.id),
  quantity: integer("quantity").notNull(),
  unitPriceCents: integer("unit_price_cents").notNull(),
  titleSnapshot: text("title_snapshot").notNull(),
  addedAt: timestamp("added_at", { withTimezone: true }).notNull().defaultNow()
}, (table) => ({
  byCart: index("cart_lines_cart_idx").on(table.cartId)
}));

export const orders = pgTable("orders", {
  id: uuid("id").primaryKey().defaultRandom(),
  customerId: uuid("customer_id").notNull().references(() => customers.id),
  reference: text("reference").notNull(),
  status: text("status").notNull().default("pending"),
  currency: text("currency").notNull().default("EUR"),
  subtotalCents: integer("subtotal_cents").notNull(),
  shippingCents: integer("shipping_cents").notNull().default(0),
  taxCents: integer("tax_cents").notNull().default(0),
  totalCents: integer("total_cents").notNull(),
  billingAddress: jsonb("billing_address").$type<Record<string, string>>(),
  placedAt: timestamp("placed_at", { withTimezone: true }).notNull().defaultNow()
}, (table) => ({
  referenceKey: uniqueIndex("orders_reference_key").on(table.reference),
  byCustomer: index("orders_customer_idx").on(table.customerId)
}));

export const orderLines = pgTable("order_lines", {
  id: uuid("id").primaryKey().defaultRandom(),
  orderId: uuid("order_id").notNull().references(() => orders.id),
  sku: text("sku").notNull(),
  titleSnapshot: text("title_snapshot").notNull(),
  quantity: integer("quantity").notNull(),
  unitPriceCents: integer("unit_price_cents").notNull()
}, (table) => ({
  byOrder: index("order_lines_order_idx").on(table.orderId)
}));

export const shipments = pgTable("shipments", {
  id: uuid("id").primaryKey().defaultRandom(),
  orderId: uuid("order_id").notNull().references(() => orders.id),
  carrier: text("carrier").notNull(),
  trackingCode: text("tracking_code"),
  status: text("status").notNull().default("label_created"),
  shippedAt: timestamp("shipped_at", { withTimezone: true })
}, (table) => ({
  byOrder: index("shipments_order_idx").on(table.orderId)
}));

export const giftCards = pgTable("gift_cards", {
  id: uuid("id").primaryKey().defaultRandom(),
  codeHash: text("code_hash").notNull(),
  balanceCents: integer("balance_cents").notNull(),
  currency: text("currency").notNull().default("EUR"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  disabledAt: timestamp("disabled_at", { withTimezone: true })
}, (table) => ({
  codeKey: uniqueIndex("gift_cards_code_hash_key").on(table.codeHash)
}));

export const giftCardLedger = pgTable("gift_card_ledger", {
  id: uuid("id").primaryKey().defaultRandom(),
  giftCardId: uuid("gift_card_id").notNull().references(() => giftCards.id),
  orderId: uuid("order_id").references(() => orders.id),
  deltaCents: integer("delta_cents").notNull(),
  memo: text("memo"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
});

export const storeCredit = pgTable("store_credit", {
  id: uuid("id").primaryKey().defaultRandom(),
  customerId: uuid("customer_id").notNull().references(() => customers.id),
  balanceCents: integer("balance_cents").notNull().default(0),
  currency: text("currency").notNull().default("EUR"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
}, (table) => ({
  customerKey: uniqueIndex("store_credit_customer_key").on(table.customerId)
}));

export const storeCreditLedger = pgTable("store_credit_ledger", {
  id: uuid("id").primaryKey().defaultRandom(),
  customerId: uuid("customer_id").notNull().references(() => customers.id),
  deltaCents: integer("delta_cents").notNull(),
  reason: text("reason").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
});

export const licenses = pgTable("licenses", {
  id: uuid("id").primaryKey().defaultRandom(),
  customerId: uuid("customer_id").notNull().references(() => customers.id),
  orderId: uuid("order_id").notNull().references(() => orders.id),
  bundleId: text("bundle_id").notNull(),
  token: text("token").notNull(),
  downloadsUsed: integer("downloads_used").notNull().default(0),
  downloadsAllowed: integer("downloads_allowed").notNull().default(25),
  revokedAt: timestamp("revoked_at", { withTimezone: true })
}, (table) => ({
  tokenKey: uniqueIndex("licenses_token_key").on(table.token)
}));

export const ordersRelations = relations(orders, ({ many, one }) => ({
  lines: many(orderLines),
  shipments: many(shipments),
  customer: one(customers, { fields: [orders.customerId], references: [customers.id] })
}));
