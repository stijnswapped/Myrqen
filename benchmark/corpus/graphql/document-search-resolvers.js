"use strict";

const gql = require("graphql-tag");
const { GraphQLError } = require("graphql");
const GraphQLJSON = require("graphql-type-json");
const { getCollection } = require("../lib/mongo");

const typeDefs = gql`
  scalar JSON

  type Document {
    id: ID!
    title: String!
    status: String!
    ownerEmail: String!
    updatedAt: String!
  }

  type DocumentPage {
    nodes: [Document!]!
    total: Int!
  }

  extend type Query {
    documents(filter: JSON, sort: String, first: Int, after: Int): DocumentPage!
  }
`;

const SORT_FIELDS = {
  updated: "updatedAt",
  created: "createdAt",
  title: "title",
};

function requireViewer(context) {
  if (!context.viewer) {
    throw new GraphQLError("Sign in to continue", {
      extensions: { code: "UNAUTHENTICATED", http: { status: 401 } },
    });
  }
  return context.viewer;
}

const resolvers = {
  JSON: GraphQLJSON,

  Query: {
    // Library search. The web client sends the facet panel state as `filter`
    // so new facets do not need a schema change on every release.
    documents: async (_parent, args, context) => {
      const viewer = requireViewer(context);
      const { filter = {}, sort = "updated", first = 25, after = 0 } = args;

      const documents = await getCollection("documents");
      const sortField = SORT_FIELDS[sort] || "updatedAt";
      const pageSize = Math.min(Math.max(first, 1), 100);

      const query = {
        workspaceId: viewer.workspaceId,
        deletedAt: null,
        ...filter,
      };

      const [nodes, total] = await Promise.all([
        documents
          .find(query)
          .sort({ [sortField]: -1 })
          .skip(Math.max(after, 0))
          .limit(pageSize)
          .toArray(),
        documents.countDocuments(query),
      ]);

      return {
        nodes: nodes.map((doc) => ({ ...doc, id: String(doc._id) })),
        total,
      };
    },
  },
};

module.exports = { typeDefs, resolvers };
