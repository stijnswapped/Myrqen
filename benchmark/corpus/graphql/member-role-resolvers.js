"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");
const audit = require("../lib/audit");

const typeDefs = gql`
  enum WorkspaceRole {
    VIEWER
    EDITOR
    ADMIN
    OWNER
  }

  type Membership {
    id: ID!
    workspaceId: ID!
    userId: ID!
    role: WorkspaceRole!
    updatedAt: String!
  }

  extend type Mutation {
    updateMemberRole(workspaceId: ID!, userId: ID!, role: WorkspaceRole!): Membership!
    transferWorkspaceOwnership(workspaceId: ID!, userId: ID!): Membership!
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

async function assertOwner(viewer, workspaceId) {
  const membership = await prisma.membership.findFirst({
    where: { workspaceId, userId: viewer.id, role: "OWNER" },
  });
  if (!membership) {
    throw new GraphQLError("Only the workspace owner can do that", {
      extensions: { code: "FORBIDDEN", http: { status: 403 } },
    });
  }
  return membership;
}

const resolvers = {
  Mutation: {
    // Members table: the role dropdown next to each person.
    updateMemberRole: async (_parent, { workspaceId, userId, role }, context) => {
      const viewer = requireViewer(context);

      const target = await prisma.membership.findFirst({
        where: { workspaceId, userId },
      });
      if (!target) {
        throw new GraphQLError("That person is not in this workspace", {
          extensions: { code: "NOT_FOUND", http: { status: 404 } },
        });
      }

      const updated = await prisma.membership.update({
        where: { id: target.id },
        data: { role, updatedAt: new Date() },
      });

      await audit.record({
        actorId: viewer.id,
        workspaceId,
        action: "membership.role_changed",
        metadata: { userId, from: target.role, to: role },
      });

      return updated;
    },

    // "Make owner" action in the members table overflow menu.
    transferWorkspaceOwnership: async (_parent, { workspaceId, userId }, context) => {
      const viewer = requireViewer(context);
      const current = await assertOwner(viewer, workspaceId);

      const [, promoted] = await prisma.$transaction([
        prisma.membership.update({
          where: { id: current.id },
          data: { role: "ADMIN" },
        }),
        prisma.membership.update({
          where: { workspaceId_userId: { workspaceId, userId } },
          data: { role: "OWNER" },
        }),
      ]);

      await audit.record({
        actorId: viewer.id,
        workspaceId,
        action: "workspace.ownership_transferred",
        metadata: { userId },
      });

      return promoted;
    },
  },
};

module.exports = { typeDefs, resolvers };
