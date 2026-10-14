import {
  boolean,
  date,
  index,
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core'

export const portalRole = pgEnum('portal_role', ['tenant', 'landlord', 'agent', 'admin'])
export const payoutState = pgEnum('payout_state', ['pending', 'approved', 'settled', 'failed'])
export const maintenanceState = pgEnum('maintenance_state', [
  'reported',
  'triaged',
  'scheduled',
  'resolved',
])
export const documentKind = pgEnum('document_kind', [
  'lease',
  'statement',
  'inspection_report',
  'certificate',
])

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 320 }).notNull().unique(),
    fullName: varchar('full_name', { length: 200 }).notNull(),
    role: portalRole('role').notNull().default('tenant'),
    landlordId: uuid('landlord_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({ landlordIdx: index('users_landlord_idx').on(table.landlordId) }),
)

export const landlords = pgTable('landlords', {
  id: uuid('id').primaryKey().defaultRandom(),
  tradingName: varchar('trading_name', { length: 200 }).notNull(),
  payoutIban: varchar('payout_iban', { length: 34 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const tenancies = pgTable(
  'tenancies',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    reference: varchar('reference', { length: 24 }).notNull().unique(),
    propertyLabel: varchar('property_label', { length: 240 }).notNull(),
    tenantId: uuid('tenant_id').notNull(),
    landlordId: uuid('landlord_id').notNull(),
    startsOn: date('starts_on').notNull(),
    endsOn: date('ends_on'),
    rentCents: integer('rent_cents').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantIdx: index('tenancies_tenant_idx').on(table.tenantId),
    landlordIdx: index('tenancies_landlord_idx').on(table.landlordId),
  }),
)

export const leases = pgTable('leases', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenancyId: uuid('tenancy_id').notNull(),
  signedOn: date('signed_on'),
  noticeDays: integer('notice_days').notNull().default(60),
  depositCents: integer('deposit_cents').notNull().default(0),
  documentId: uuid('document_id'),
})

export const rentStatements = pgTable(
  'rent_statements',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenancyId: uuid('tenancy_id').notNull(),
    periodStart: date('period_start').notNull(),
    periodEnd: date('period_end').notNull(),
    dueCents: integer('due_cents').notNull(),
    paidCents: integer('paid_cents').notNull().default(0),
    settledOn: date('settled_on'),
  },
  (table) => ({ tenancyIdx: index('rent_statements_tenancy_idx').on(table.tenancyId) }),
)

export const maintenanceRequests = pgTable(
  'maintenance_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenancyId: uuid('tenancy_id').notNull(),
    reportedBy: uuid('reported_by').notNull(),
    summary: varchar('summary', { length: 240 }).notNull(),
    detail: text('detail'),
    state: maintenanceState('state').notNull().default('reported'),
    contractorNote: text('contractor_note'),
    estimateCents: integer('estimate_cents'),
    landlordApproved: boolean('landlord_approved').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({ tenancyIdx: index('maintenance_requests_tenancy_idx').on(table.tenancyId) }),
)

export const maintenancePhotos = pgTable('maintenance_photos', {
  id: uuid('id').primaryKey().defaultRandom(),
  requestId: uuid('request_id').notNull(),
  storageKey: varchar('storage_key', { length: 512 }).notNull(),
  originalName: varchar('original_name', { length: 255 }).notNull(),
  mimeType: varchar('mime_type', { length: 100 }).notNull(),
  sizeBytes: integer('size_bytes').notNull(),
  uploadedBy: uuid('uploaded_by').notNull(),
  uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull().defaultNow(),
})

export const payouts = pgTable(
  'payouts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    reference: varchar('reference', { length: 24 }).notNull().unique(),
    landlordId: uuid('landlord_id').notNull(),
    tenancyId: uuid('tenancy_id').notNull(),
    amountCents: integer('amount_cents').notNull(),
    feeCents: integer('fee_cents').notNull().default(0),
    state: payoutState('state').notNull().default('pending'),
    settledOn: date('settled_on'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({ landlordIdx: index('payouts_landlord_idx').on(table.landlordId) }),
)

export const documents = pgTable(
  'documents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenancyId: uuid('tenancy_id').notNull(),
    kind: documentKind('kind').notNull(),
    fileName: varchar('file_name', { length: 255 }).notNull(),
    storageKey: varchar('storage_key', { length: 512 }).notNull(),
    mimeType: varchar('mime_type', { length: 100 }).notNull(),
    sizeBytes: integer('size_bytes').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({ tenancyIdx: index('documents_tenancy_idx').on(table.tenancyId) }),
)

export const inspections = pgTable('inspections', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenancyId: uuid('tenancy_id').notNull(),
  scheduledBy: uuid('scheduled_by').notNull(),
  inspectorName: varchar('inspector_name', { length: 120 }).notNull(),
  slotStart: timestamp('slot_start', { withTimezone: true }).notNull(),
  slotEnd: timestamp('slot_end', { withTimezone: true }).notNull(),
  notes: text('notes'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const inspectionPartners = pgTable('inspection_partners', {
  id: uuid('id').primaryKey().defaultRandom(),
  landlordId: uuid('landlord_id').notNull(),
  displayName: varchar('display_name', { length: 120 }).notNull(),
  webhookUrl: varchar('webhook_url', { length: 512 }).notNull(),
  enabled: boolean('enabled').notNull().default(true),
})
