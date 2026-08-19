"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");
const billing = require("../lib/billing");
const audit = require("../lib/audit");

const typeDefs = gql`
  enum PlanTier {
    FREE
    TEAM
    BUSINESS
    ENTERPRISE
  }

  type Subscription {
    id: ID!
    workspaceId: ID!
    tier: PlanTier!
    seats: Int!
    renewsAt: String
    updatedAt: String!
  }

  extend type Mutation {
    changeWorkspacePlan(workspaceId: ID!, tier: PlanTier!, seats: Int!): Subscription!
  }
`;

const BILLING_ROLES = ["OWNER", "ADMIN"];

function requireViewer(context) {
  if (!context.viewer) {
    throw new GraphQLError("Sign in to continue", {
      extensions: { code: "UNAUTHENTICATED", http: { status: 401 } },
    });
  }
  return context.viewer;
}

async function assertBillingRole(viewer, workspaceId) {
  const membership = await prisma.membership.findFirst({
    where: { workspaceId, userId: viewer.id, role: { in: BILLING_ROLES } },
  });
  if (!membership) {
    throw new GraphQLError("You do not manage billing for this workspace", {
      extensions: { code: "FORBIDDEN", http: { status: 403 } },
    });
  }
  return membership;
}

const resolvers = {
  Mutation: {
    // Plan picker in workspace settings; seats are pro-rated by the provider.
    changeWorkspacePlan: async (_parent, { workspaceId, tier, seats }, context) => {
      const viewer = requireViewer(context);
      await assertBillingRole(viewer, workspaceId);

      if (!Number.isInteger(seats) || seats < 1 || seats > 500) {
        throw new GraphQLError("Seat count must be between 1 and 500", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }

      const current = await prisma.subscription.findUnique({ where: { workspaceId } });
      if (!current) {
        throw new GraphQLError("This workspace has no subscription", {
          extensions: { code: "NOT_FOUND", http: { status: 404 } },
        });
      }

      await billing.updateSubscription(current.providerId, { tier, seats });

      const updated = await prisma.subscription.update({
        where: { workspaceId },
        data: { tier, seats, updatedAt: new Date() },
      });

      await audit.record({
        actorId: viewer.id,
        workspaceId,
        action: "subscription.plan_changed",
        metadata: { from: current.tier, to: tier, seats },
      });

      return updated;
    },
  },
};

module.exports = { typeDefs, resolvers };
