import { relations } from 'drizzle-orm';
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

export const userRole = pgEnum('user_role', ['ops', 'customs', 'admin']);

export const consignmentStatus = pgEnum('consignment_status', [
  'draft',
  'booked',
  'in_transit',
  'at_customs',
  'out_for_delivery',
  'delivered',
  'cancelled',
]);

export const bookingStatus = pgEnum('booking_status', ['requested', 'confirmed', 'rolled', 'cancelled']);

export const amendmentStatus = pgEnum('amendment_status', ['open', 'accepted', 'rejected']);

export const customsDocumentKind = pgEnum('customs_document_kind', [
  'declaration',
  'commercial_invoice',
  'packing_list',
  'certificate_of_origin',
  'gateway_response',
]);

/** A forwarding branch. Everything in the platform hangs off one of these. */
export const forwarders = pgTable('forwarders', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  eoriNumber: varchar('eori_number', { length: 20 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    forwarderId: uuid('forwarder_id')
      .notNull()
      .references(() => forwarders.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    fullName: text('full_name').notNull(),
    role: userRole('role').notNull().default('ops'),
    disabledAt: timestamp('disabled_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('users_email_idx').on(table.email)],
);

/**
 * Server side sessions. The cookie only ever carries `sessions.id`, which is a
 * 32 byte random token, and the cookie itself is signed by cookie-parser.
 */
export const sessions = pgTable(
  'sessions',
  {
    id: text('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    issuedAt: timestamp('issued_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    userAgent: text('user_agent'),
    remoteAddress: varchar('remote_address', { length: 64 }),
  },
  (table) => [index('sessions_user_idx').on(table.userId)],
);

/** Carrier staff who log into the partner portal to accept bookings. */
export const carrierPartners = pgTable(
  'carrier_partners',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    forwarderId: uuid('forwarder_id')
      .notNull()
      .references(() => forwarders.id, { onDelete: 'cascade' }),
    carrierCode: varchar('carrier_code', { length: 16 }).notNull(),
    displayName: text('display_name').notNull(),
    scopes: jsonb('scopes').$type<string[]>().notNull().default(['bookings:read']),
    suspendedAt: timestamp('suspended_at', { withTimezone: true }),
  },
  (table) => [index('carrier_partners_code_idx').on(table.carrierCode)],
);

export const consignments = pgTable(
  'consignments',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    forwarderId: uuid('forwarder_id')
      .notNull()
      .references(() => forwarders.id, { onDelete: 'cascade' }),
    reference: varchar('reference', { length: 32 }).notNull(),
    status: consignmentStatus('status').notNull().default('draft'),
    shipperName: text('shipper_name').notNull(),
    consigneeName: text('consignee_name').notNull(),
    originPort: varchar('origin_port', { length: 8 }).notNull(),
    destinationPort: varchar('destination_port', { length: 8 }).notNull(),
    incoterm: varchar('incoterm', { length: 8 }).notNull(),
    grossWeightKg: integer('gross_weight_kg').notNull(),
    declaredValueCents: integer('declared_value_cents').notNull().default(0),
    /** Per consignment folder inside the customs document bucket. */
    customsFolder: text('customs_folder').notNull(),
    bookedAt: timestamp('booked_at', { withTimezone: true }).notNull().defaultNow(),
    lastCarrierUpdateAt: timestamp('last_carrier_update_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('consignments_reference_idx').on(table.reference),
    index('consignments_forwarder_idx').on(table.forwarderId, table.status),
  ],
);

export const carrierBookings = pgTable(
  'carrier_bookings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    consignmentId: uuid('consignment_id')
      .notNull()
      .references(() => consignments.id, { onDelete: 'cascade' }),
    carrierCode: varchar('carrier_code', { length: 16 }).notNull(),
    serviceLevel: varchar('service_level', { length: 24 }).notNull(),
    status: bookingStatus('status').notNull().default('requested'),
    agreedRateCents: integer('agreed_rate_cents').notNull().default(0),
    currency: varchar('currency', { length: 3 }).notNull().default('EUR'),
    requestedPickupAt: timestamp('requested_pickup_at', { withTimezone: true }),
    confirmedAt: timestamp('confirmed_at', { withTimezone: true }),
    approvedBy: uuid('approved_by').references(() => users.id),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('carrier_bookings_consignment_idx').on(table.consignmentId)],
);

export const bookingAmendments = pgTable(
  'booking_amendments',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    bookingId: uuid('booking_id')
      .notNull()
      .references(() => carrierBookings.id, { onDelete: 'cascade' }),
    requestedPickupAt: timestamp('requested_pickup_at', { withTimezone: true }),
    requestedDeliveryAt: timestamp('requested_delivery_at', { withTimezone: true }),
    handlingNotes: text('handling_notes'),
    status: amendmentStatus('status').notNull().default('open'),
    approvedBy: uuid('approved_by').references(() => users.id),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('booking_amendments_booking_idx').on(table.bookingId)],
);

export const bookingAuditLog = pgTable('booking_audit_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  bookingId: uuid('booking_id')
    .notNull()
    .references(() => carrierBookings.id, { onDelete: 'cascade' }),
  actorId: uuid('actor_id').references(() => users.id),
  changedKeys: jsonb('changed_keys').$type<string[]>().notNull(),
  recordedAt: timestamp('recorded_at', { withTimezone: true }).notNull().defaultNow(),
});

export const customsDocuments = pgTable(
  'customs_documents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    consignmentId: uuid('consignment_id')
      .notNull()
      .references(() => consignments.id, { onDelete: 'cascade' }),
    kind: customsDocumentKind('kind').notNull(),
    fileName: text('file_name').notNull(),
    sizeBytes: integer('size_bytes').notNull().default(0),
    uploadedBy: uuid('uploaded_by').references(() => users.id),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('customs_documents_consignment_idx').on(table.consignmentId)],
);

export const documentAccessLog = pgTable('document_access_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  consignmentId: uuid('consignment_id')
    .notNull()
    .references(() => consignments.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').references(() => users.id),
  fileName: text('file_name').notNull(),
  servedAt: timestamp('served_at', { withTimezone: true }).notNull().defaultNow(),
});

export const deliveryProofs = pgTable(
  'delivery_proofs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    consignmentId: uuid('consignment_id')
      .notNull()
      .references(() => consignments.id, { onDelete: 'cascade' }),
    /** Folder handed out by the upload endpoint, relative to the proof bucket. */
    storageFolder: text('storage_folder').notNull(),
    fileName: text('file_name').notNull(),
    contentType: varchar('content_type', { length: 64 }).notNull(),
    capturedBy: text('captured_by').notNull(),
    signedForBy: text('signed_for_by'),
    capturedAt: timestamp('captured_at', { withTimezone: true }).notNull(),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('delivery_proofs_consignment_idx').on(table.consignmentId)],
);

export const rateCards = pgTable(
  'rate_cards',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    forwarderId: uuid('forwarder_id')
      .notNull()
      .references(() => forwarders.id, { onDelete: 'cascade' }),
    laneCode: varchar('lane_code', { length: 32 }).notNull(),
    carrierCode: varchar('carrier_code', { length: 16 }).notNull(),
    serviceLevel: varchar('service_level', { length: 24 }).notNull(),
    currency: varchar('currency', { length: 3 }).notNull().default('EUR'),
    baseCents: integer('base_cents').notNull(),
    fuelSurchargePct: integer('fuel_surcharge_pct').notNull().default(0),
    validFrom: timestamp('valid_from', { withTimezone: true }).notNull(),
    validTo: timestamp('valid_to', { withTimezone: true }),
    isPublished: boolean('is_published').notNull().default(false),
  },
  (table) => [
    index('rate_cards_forwarder_lane_idx').on(table.forwarderId, table.laneCode),
    index('rate_cards_carrier_idx').on(table.carrierCode),
  ],
);

export const trackingEvents = pgTable(
  'tracking_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    consignmentId: uuid('consignment_id')
      .notNull()
      .references(() => consignments.id, { onDelete: 'cascade' }),
    code: varchar('code', { length: 24 }).notNull(),
    description: text('description').notNull(),
    location: varchar('location', { length: 64 }),
    source: varchar('source', { length: 24 }).notNull().default('desk'),
    occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull(),
    recordedAt: timestamp('recorded_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('tracking_events_consignment_idx').on(table.consignmentId, table.occurredAt)],
);

export const carrierWebhookDeliveries = pgTable('carrier_webhook_deliveries', {
  id: uuid('id').primaryKey().defaultRandom(),
  carrierCode: varchar('carrier_code', { length: 16 }).notNull(),
  eventId: text('event_id').notNull(),
  signatureVerified: boolean('signature_verified').notNull(),
  payload: jsonb('payload').notNull(),
  receivedAt: timestamp('received_at', { withTimezone: true }).notNull().defaultNow(),
});

export const consignmentRelations = relations(consignments, ({ one, many }) => ({
  forwarder: one(forwarders, { fields: [consignments.forwarderId], references: [forwarders.id] }),
  bookings: many(carrierBookings),
  documents: many(customsDocuments),
  events: many(trackingEvents),
}));

export const bookingRelations = relations(carrierBookings, ({ one, many }) => ({
  consignment: one(consignments, {
    fields: [carrierBookings.consignmentId],
    references: [consignments.id],
  }),
  amendments: many(bookingAmendments),
}));
