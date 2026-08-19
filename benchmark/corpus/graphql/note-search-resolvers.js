"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const GraphQLJSON = require("graphql-type-json");
const { getCollection } = require("../lib/mongo");

const typeDefs = gql`
  scalar JSON

  type Note {
    id: ID!
    subject: String!
    state: String!
    authorEmail: String!
    createdAt: String!
  }

  type NotePage {
    nodes: [Note!]!
    total: Int!
  }

  extend type Query {
    notes(filter: JSON, sort: String, first: Int, after: Int): NotePage!
  }
`;

const SORT_FIELDS = {
  created: "createdAt",
  updated: "updatedAt",
  subject: "subject",
};

// Facet name -> stored field; unknown keys from the client are ignored.
const FILTER_FIELDS = {
  state: "state",
  authorEmail: "authorEmail",
  labelId: "labelId",
};

function requireViewer(context) {
  if (!context.viewer) {
    throw new GraphQLError("Sign in to continue", {
      extensions: { code: "UNAUTHENTICATED", http: { status: 401 } },
    });
  }
  return context.viewer;
}

function buildFacetQuery(filter) {
  const conditions = {};
  for (const [key, field] of Object.entries(FILTER_FIELDS)) {
    const value = filter[key];
    if (value === undefined || value === null) continue;
    if (typeof value !== "string" && typeof value !== "number") {
      throw new GraphQLError(`Filter "${key}" must be a single value`, {
        extensions: { code: "BAD_USER_INPUT" },
      });
    }
    conditions[field] = String(value);
  }
  return conditions;
}

const resolvers = {
  JSON: GraphQLJSON,

  Query: {
    // Notes search, driven by the same facet panel as the library screen.
    notes: async (_parent, args, context) => {
      const viewer = requireViewer(context);
      const { filter = {}, sort = "created", first = 25, after = 0 } = args;

      const notes = await getCollection("notes");
      const sortField = SORT_FIELDS[sort] || "createdAt";
      const pageSize = Math.min(Math.max(first, 1), 100);

      const query = {
        ...buildFacetQuery(filter),
        workspaceId: viewer.workspaceId,
        deletedAt: null,
      };

      const [nodes, total] = await Promise.all([
        notes
          .find(query)
          .sort({ [sortField]: -1 })
          .skip(Math.max(after, 0))
          .limit(pageSize)
          .toArray(),
        notes.countDocuments(query),
      ]);

      return {
        nodes: nodes.map((note) => ({ ...note, id: String(note._id) })),
        total,
      };
    },
  },
};

module.exports = { typeDefs, resolvers };
