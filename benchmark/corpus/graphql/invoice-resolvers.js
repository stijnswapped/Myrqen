"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const typeDefs = gql`
  enum InvoiceStatus {
    DRAFT
    OPEN
    PAID
    VOID
  }

  type InvoiceLineItem {
    id: ID!
    description: String!
    quantity: Int!
    unitPriceCents: Int!
  }

  type Invoice {
    id: ID!
    number: String!
    status: InvoiceStatus!
    totalCents: Int!
    issuedAt: String!
    dueAt: String
    billingEmail: String
    lineItems: [InvoiceLineItem!]!
  }

  extend type Query {
    invoices(status: InvoiceStatus): [Invoice!]!
    invoice(id: ID!): Invoice
  }
`;

function requireViewer(context) {
  if (!context.viewer) {
    throw new GraphQLError("Sign in to continue", {
      extensions: { code: "UNAUTHENTICATED", http: { status: 401 } },
    });
  }
  return context.viewer;
}

const resolvers = {
  Query: {
    // Billing screen: the account's invoices, newest first.
    invoices: async (_parent, args, context) => {
      const viewer = requireViewer(context);
      return prisma.invoice.findMany({
        where: {
          accountId: viewer.accountId,
          ...(args.status ? { status: args.status } : {}),
        },
        orderBy: { issuedAt: "desc" },
        take: 50,
      });
    },

    // Invoice drawer, opened from a row on the billing screen.
    invoice: async (_parent, { id }, context) => {
      requireViewer(context);
      return prisma.invoice.findUnique({
        where: { id },
      });
    },
  },

  Invoice: {
    lineItems: (invoice) =>
      prisma.invoiceLineItem.findMany({
        where: { invoiceId: invoice.id },
        orderBy: { position: "asc" },
      }),
  },
};

module.exports = { typeDefs, resolvers };
