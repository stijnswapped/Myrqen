/**
 * MikroORM entities for the Atelier marketplace module.
 *
 * The module owns its own slice of the Postgres schema (every table is prefixed
 * `atelier_`) and its loader registers the MikroORM EntityManager on the Medusa
 * container under MARKETPLACE_MANAGER, which is how the API layer and the
 * workflow steps reach it without going through the generated service methods.
 */
import {
  BeforeCreate,
  Collection,
  Entity,
  Enum,
  Index,
  ManyToOne,
  OneToMany,
  PrimaryKey,
  Property,
} from "@mikro-orm/core"
import { generateEntityId } from "@medusajs/framework/utils"

/** Container registration name, see ./../loaders/manager.ts. */
export const MARKETPLACE_MANAGER = "marketplaceManager"

export type VendorOnboardingState = "pending" | "review" | "live" | "suspended"
export type VendorMemberRole = "owner" | "finance" | "viewer"
export type PayoutBatchStatus = "draft" | "approved" | "paid" | "reversed"
export type RegistryVisibility = "private" | "link" | "public"
export type VendorDocumentKind = "tax_form" | "certificate" | "remittance_advice"

/**
 * An atelier: an independent workshop that consigns homeware through the store.
 */
@Entity({ tableName: "atelier_vendor" })
export class Vendor {
  @PrimaryKey({ columnType: "text" })
  id!: string

  @Property({ columnType: "text" })
  @Index({ name: "IDX_atelier_vendor_handle" })
  handle!: string

  @Property({ columnType: "text" })
  display_name!: string

  /** Public JSON product feed the atelier maintains; polled by the sync workflow. */
  @Property({ columnType: "text", nullable: true })
  feed_url: string | null = null

  /** Where the atelier's brand logo and lookbook images are pulled from. */
  @Property({ columnType: "text", nullable: true })
  asset_base_url: string | null = null

  /** Sales channel the atelier's products are published to. */
  @Property({ columnType: "text" })
  sales_channel_id!: string

  @Property({ columnType: "text", nullable: true })
  payout_iban_last4: string | null = null

  @Property({ columnType: "integer", default: 1500 })
  commission_bps = 1500

  @Property({ columnType: "boolean", default: false })
  is_payout_enabled = false

  @Enum({
    items: () => ["pending", "review", "live", "suspended"],
    default: "pending",
  })
  onboarding_state: VendorOnboardingState = "pending"

  @OneToMany(() => VendorMember, (member) => member.vendor)
  members = new Collection<VendorMember>(this)

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @Property({
    columnType: "timestamptz",
    onUpdate: () => new Date(),
    nullable: true,
  })
  updated_at: Date | null = null

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "aven")
  }
}

/**
 * Links a Medusa `user` actor to the atelier whose books it may look at.
 */
@Entity({ tableName: "atelier_vendor_member" })
export class VendorMember {
  @PrimaryKey({ columnType: "text" })
  id!: string

  @ManyToOne(() => Vendor, { fieldName: "vendor_id", columnType: "text" })
  vendor!: Vendor

  /** Medusa `user` actor id of the staff account. */
  @Property({ columnType: "text" })
  @Index({ name: "IDX_atelier_vendor_member_user" })
  user_id!: string

  @Enum({ items: () => ["owner", "finance", "viewer"], default: "viewer" })
  role: VendorMemberRole = "viewer"

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "avmem")
  }
}

/**
 * One remittance period for one atelier. Finance approves it, then the payout
 * provider pays it out.
 */
@Entity({ tableName: "atelier_payout_batch" })
export class PayoutBatch {
  @PrimaryKey({ columnType: "text" })
  id!: string

  @ManyToOne(() => Vendor, { fieldName: "vendor_id", columnType: "text" })
  vendor!: Vendor

  @Property({ columnType: "date" })
  period_start!: Date

  @Property({ columnType: "date" })
  period_end!: Date

  @Property({ columnType: "integer", default: 0 })
  gross_cents = 0

  @Property({ columnType: "integer", default: 0 })
  commission_cents = 0

  @Property({ columnType: "integer", default: 0 })
  net_cents = 0

  @Property({ columnType: "text", default: "eur" })
  currency_code = "eur"

  @Enum({
    items: () => ["draft", "approved", "paid", "reversed"],
    default: "draft",
  })
  status: PayoutBatchStatus = "draft"

  @Property({ columnType: "text", nullable: true })
  approved_by: string | null = null

  @Property({ columnType: "text", nullable: true })
  note: string | null = null

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "apb")
  }
}

/**
 * A customer's gift registry (wedding, housewarming, new studio).
 */
@Entity({ tableName: "atelier_gift_registry" })
export class GiftRegistry {
  @PrimaryKey({ columnType: "text" })
  id!: string

  /** Medusa `customer` actor id of the owner. */
  @Property({ columnType: "text" })
  @Index({ name: "IDX_atelier_gift_registry_customer" })
  customer_id!: string

  @Property({ columnType: "text" })
  title!: string

  @Property({ columnType: "timestamptz", nullable: true })
  event_date: Date | null = null

  @Enum({
    items: () => ["private", "link", "public"],
    default: "private",
  })
  visibility: RegistryVisibility = "private"

  @Property({ columnType: "text", nullable: true })
  shipping_address_line: string | null = null

  @Property({ columnType: "text", nullable: true })
  shipping_postal_code: string | null = null

  @Property({ columnType: "text", nullable: true })
  recipient_email: string | null = null

  /** Only ever shown to the owner. */
  @Property({ columnType: "text", nullable: true })
  private_note: string | null = null

  /** Goodwill balance support can grant; spendable at checkout. */
  @Property({ columnType: "integer", default: 0 })
  store_credit_cents = 0

  /** Set by support once the event has been confirmed by phone. */
  @Property({ columnType: "boolean", default: false })
  is_verified = false

  @Property({ columnType: "text" })
  sales_channel_id!: string

  @OneToMany(() => RegistryClaim, (claim) => claim.registry)
  claims = new Collection<RegistryClaim>(this)

  @Property({ columnType: "jsonb", nullable: true })
  metadata: Record<string, unknown> | null = null

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @Property({
    columnType: "timestamptz",
    onUpdate: () => new Date(),
    nullable: true,
  })
  updated_at: Date | null = null

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "areg")
  }
}

/**
 * A guest claiming a line off a registry, so two guests don't buy the same vase.
 */
@Entity({ tableName: "atelier_registry_claim" })
export class RegistryClaim {
  @PrimaryKey({ columnType: "text" })
  id!: string

  @ManyToOne(() => GiftRegistry, { fieldName: "registry_id", columnType: "text" })
  registry!: GiftRegistry

  @Property({ columnType: "text" })
  variant_id!: string

  @Property({ columnType: "integer", default: 1 })
  quantity = 1

  @Property({ columnType: "text", nullable: true })
  claimed_by_email: string | null = null

  @Property({ columnType: "text", nullable: true })
  gift_message: string | null = null

  @Property({ columnType: "boolean", default: false })
  is_fulfilled = false

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "aclm")
  }
}

/**
 * Scanned paperwork for an atelier. Stored on disk as a folder of pages plus
 * whatever the atelier attached to it.
 */
@Entity({ tableName: "atelier_vendor_document" })
export class VendorDocument {
  @PrimaryKey({ columnType: "text" })
  id!: string

  @ManyToOne(() => Vendor, { fieldName: "vendor_id", columnType: "text" })
  vendor!: Vendor

  @Enum({ items: () => ["tax_form", "certificate", "remittance_advice"] })
  kind!: VendorDocumentKind

  @Property({ columnType: "text" })
  title!: string

  /** Folder under the document root, e.g. "aven_01HZ.../2026-Q1-tax". */
  @Property({ columnType: "text" })
  storage_folder!: string

  @Property({ columnType: "integer", default: 1 })
  page_count = 1

  @Property({ columnType: "text" })
  uploaded_by!: string

  @Property({ columnType: "timestamptz", onCreate: () => new Date() })
  created_at: Date = new Date()

  @BeforeCreate()
  assignId() {
    this.id = generateEntityId(this.id, "adoc")
  }
}
