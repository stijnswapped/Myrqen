"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const typeDefs = gql`
  enum StatementPeriod {
    MONTHLY
    QUARTERLY
  }

  type StatementEntry {
    id: ID!
    label: String!
    amountCents: Int!
    postedAt: String!
  }

  type Statement {
    id: ID!
    reference: String!
    period: StatementPeriod!
    openingBalanceCents: Int!
    closingBalanceCents: Int!
    generatedAt: String!
    entries: [StatementEntry!]!
  }

  extend type Query {
    statements(period: StatementPeriod): [Statement!]!
    statement(id: ID!): Statement
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
    // Statements tab: everything we have generated for the account.
    statements: async (_parent, args, context) => {
      const viewer = requireViewer(context);
      return prisma.statement.findMany({
        where: {
          accountId: viewer.accountId,
          ...(args.period ? { period: args.period } : {}),
        },
        orderBy: { generatedAt: "desc" },
        take: 50,
      });
    },

    // Statement drawer, opened from a row on the statements tab.
    statement: async (_parent, { id }, context) => {
      const viewer = requireViewer(context);
      return prisma.statement.findFirst({
        where: { id, accountId: viewer.accountId },
      });
    },
  },

  Statement: {
    entries: (statement) =>
      prisma.statementEntry.findMany({
        where: { statementId: statement.id },
        orderBy: { postedAt: "asc" },
      }),
  },
};

module.exports = { typeDefs, resolvers };
