"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const prisma = require("../lib/prisma");

const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 100;
const MAX_REPLIES_PER_NOTE = 25;

const typeDefs = gql`
  type TimelineReply {
    id: ID!
    body: String!
    createdAt: String!
    author: User!
  }

  type TimelineNote {
    id: ID!
    body: String!
    createdAt: String!
    author: User!
    replies: [TimelineReply!]!
  }

  type TimelineEntry {
    id: ID!
    verb: String!
    createdAt: String!
    actor: User!
    notes: [TimelineNote!]!
  }

  extend type Query {
    timeline(first: Int, afterCursor: String): [TimelineEntry!]!
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

function readPageSize(first) {
  if (first === undefined || first === null) return DEFAULT_PAGE_SIZE;
  if (!Number.isInteger(first) || first < 1) {
    throw new GraphQLError("first must be a positive integer", {
      extensions: { code: "BAD_USER_INPUT" },
    });
  }
  return Math.min(first, MAX_PAGE_SIZE);
}

const resolvers = {
  Query: {
    // Project timeline. Same feed the home page uses, scoped to one project.
    timeline: async (_parent, { first, afterCursor }, context) => {
      const viewer = requireViewer(context);
      const take = readPageSize(first);

      return prisma.timelineEntry.findMany({
        where: {
          workspaceId: viewer.workspaceId,
          ...(afterCursor ? { createdAt: { lt: new Date(afterCursor) } } : {}),
        },
        orderBy: { createdAt: "desc" },
        take,
      });
    },
  },

  TimelineEntry: {
    actor: (entry, _args, context) => context.loaders.user.load(entry.actorId),
    notes: (entry) =>
      prisma.timelineNote.findMany({
        where: { timelineEntryId: entry.id },
        orderBy: { createdAt: "asc" },
        take: MAX_PAGE_SIZE,
      }),
  },

  TimelineNote: {
    author: (note, _args, context) => context.loaders.user.load(note.authorId),
    replies: (note) =>
      prisma.timelineReply.findMany({
        where: { noteId: note.id },
        orderBy: { createdAt: "asc" },
        take: MAX_REPLIES_PER_NOTE,
      }),
  },

  TimelineReply: {
    author: (reply, _args, context) => context.loaders.user.load(reply.authorId),
  },
};

module.exports = { typeDefs, resolvers };
