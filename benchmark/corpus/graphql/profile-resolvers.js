"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const typeDefs = gql`
  type User {
    id: ID!
    email: String!
    displayName: String
    timezone: String
    locale: String
    avatarUrl: String
    role: String!
    planTier: String!
    emailVerified: Boolean!
  }

  # Shared by the account screen and the staff console.
  input UserFields {
    displayName: String
    timezone: String
    locale: String
    avatarUrl: String
    role: String
    planTier: String
    emailVerified: Boolean
  }

  extend type Mutation {
    updateProfile(input: UserFields!): User!
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
  Mutation: {
    // Account screen: name, timezone, language and avatar.
    updateProfile: async (_parent, { input }, context) => {
      const viewer = requireViewer(context);

      if (input.displayName !== undefined && input.displayName.trim().length < 2) {
        throw new GraphQLError("Display name is too short", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      const user = await prisma.user.update({
        where: { id: viewer.id },
        data: { ...input, updatedAt: new Date() },
        select: {
          id: true,
          email: true,
          displayName: true,
          timezone: true,
          locale: true,
          avatarUrl: true,
          role: true,
          planTier: true,
          emailVerified: true,
        },
      });

      return user;
    },
  },
};

module.exports = { typeDefs, resolvers };
