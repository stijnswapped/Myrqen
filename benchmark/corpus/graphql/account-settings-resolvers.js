"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const typeDefs = gql`
  type AccountSettings {
    id: ID!
    email: String!
    contactName: String
    phone: String
    weeklyDigest: Boolean!
    supportTier: String!
    isStaff: Boolean!
  }

  # Shared by the settings screen and the staff console.
  input AccountFields {
    contactName: String
    phone: String
    weeklyDigest: Boolean
    supportTier: String
    isStaff: Boolean
  }

  extend type Mutation {
    updateAccountSettings(input: AccountFields!): AccountSettings!
  }
`;

const SELF_EDITABLE = ["contactName", "phone", "weeklyDigest"];

function requireViewer(context) {
  if (!context.viewer) {
    throw new GraphQLError("Sign in to continue", {
      extensions: { code: "UNAUTHENTICATED", http: { status: 401 } },
    });
  }
  return context.viewer;
}

const resolvers = {
  Mutation: {
    // Settings screen: contact details and the digest toggle.
    updateAccountSettings: async (_parent, { input }, context) => {
      const viewer = requireViewer(context);

      const data = {};
      for (const field of SELF_EDITABLE) {
        if (input[field] !== undefined) {
          data[field] = input[field];
        }
      }

      if (data.contactName !== undefined && data.contactName.trim().length < 2) {
        throw new GraphQLError("Contact name is too short", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      if (Object.keys(data).length === 0) {
        throw new GraphQLError("Nothing to update", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      return prisma.account.update({
        where: { id: viewer.accountId },
        data: { ...data, updatedAt: new Date() },
        select: {
          id: true,
          email: true,
          contactName: true,
          phone: true,
          weeklyDigest: true,
          supportTier: true,
          isStaff: true,
        },
      });
    },
  },
};

module.exports = { typeDefs, resolvers };
