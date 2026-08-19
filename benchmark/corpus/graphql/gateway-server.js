"use strict";

const express = require("express");
const { randomUUID } = require("crypto");
const { ApolloServer } = require("@apollo/server");
const { expressMiddleware } = require("@apollo/server/express4");
const { unwrapResolverError } = require("@apollo/server/errors");
const { json } = require("body-parser");

const schema = require("./schema");
const logger = require("../lib/logger");
const { loadViewer } = require("../lib/session");

const PORT = Number.parseInt(process.env.PORT, 10) || 4100;
const isProduction = process.env.NODE_ENV === "production";

// Codes the client is allowed to branch on; anything else is a server fault.
const CLIENT_CODES = new Set([
  "BAD_USER_INPUT",
  "GRAPHQL_VALIDATION_FAILED",
  "GRAPHQL_PARSE_FAILED",
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "NOT_FOUND",
  "PERSISTED_QUERY_NOT_FOUND",
]);

async function start() {
  const app = express();

  const server = new ApolloServer({
    schema,
    introspection: !isProduction,
    // Error shaping: the client error banner and the support ticket workflow
    // both read the extensions block, so keep the field names stable.
    formatError: (formattedError, error) => {
      const cause = unwrapResolverError(error) || error;
      const code = formattedError.extensions && formattedError.extensions.code;
      const incidentId = randomUUID();

      logger.error(
        { err: cause, code, incidentId, path: formattedError.path },
        "graphql error"
      );

      if (CLIENT_CODES.has(code)) {
        return {
          message: formattedError.message,
          path: formattedError.path,
          extensions: { code, incidentId },
        };
      }

      return {
        message: "Something went wrong on our side. Quote this id to support.",
        path: formattedError.path,
        extensions: { code: "INTERNAL_SERVER_ERROR", incidentId },
      };
    },
  });

  await server.start();

  app.use(
    "/graphql",
    json({ limit: "1mb" }),
    expressMiddleware(server, {
      context: async ({ req }) => ({
        viewer: await loadViewer(req),
        requestId: req.headers["x-request-id"],
      }),
    })
  );

  app.listen(PORT, () => {
    logger.info({ port: PORT }, "graphql gateway listening");
  });
}

start().catch((err) => {
  logger.error({ err }, "graphql gateway failed to start");
  process.exit(1);
});
