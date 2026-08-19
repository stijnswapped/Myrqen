"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const typeDefs = gql`
  type Comment {
    id: ID!
    body: String!
    createdAt: String!
    author: User!
    replies: [Comment!]!
  }

  type ActivityEvent {
    id: ID!
    verb: String!
    createdAt: String!
    actor: User!
    comments: [Comment!]!
  }

  extend type Query {
    activityFeed(first: Int, afterCursor: String): [ActivityEvent!]!
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
    // Home page feed. The web client asks for 20; the mobile client asks for
    // more per page because it renders taller rows.
    activityFeed: async (_parent, { first = 20, afterCursor }, context) => {
      const viewer = requireViewer(context);

      return prisma.activityEvent.findMany({
        where: {
          workspaceId: viewer.workspaceId,
          ...(afterCursor ? { createdAt: { lt: new Date(afterCursor) } } : {}),
        },
        orderBy: { createdAt: "desc" },
        take: first,
      });
    },
  },

  ActivityEvent: {
    actor: (event, _args, context) => context.loaders.user.load(event.actorId),
    comments: (event) =>
      prisma.comment.findMany({
        where: { activityEventId: event.id, parentId: null },
        orderBy: { createdAt: "asc" },
      }),
  },

  Comment: {
    author: (comment, _args, context) => context.loaders.user.load(comment.authorId),
    replies: (comment) =>
      prisma.comment.findMany({
        where: { parentId: comment.id },
        orderBy: { createdAt: "asc" },
      }),
  },
};

module.exports = { typeDefs, resolvers };
