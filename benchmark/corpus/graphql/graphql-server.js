"use strict";

const express = require("express");
const { ApolloServer } = require("@apollo/server");
const { expressMiddleware } = require("@apollo/server/express4");
const { unwrapResolverError } = require("@apollo/server/errors");
const { json } = require("body-parser");

const schema = require("./schema");
const logger = require("../lib/logger");
const { loadViewer } = require("../lib/session");

const PORT = Number.parseInt(process.env.PORT, 10) || 4000;
const isProduction = process.env.NODE_ENV === "production";

async function start() {
  const app = express();

  const server = new ApolloServer({
    schema,
    introspection: !isProduction,
    // Error shaping: the client error banner and the support ticket workflow
    // both read the extensions block, so keep the field names stable.
    formatError: (formattedError, error) => {
      const cause = unwrapResolverError(error) || error;

      logger.error({ err: cause, path: formattedError.path }, "graphql error");

      return {
        ...formattedError,
        extensions: {
          ...formattedError.extensions,
          stacktrace: cause instanceof Error ? cause.stack.split("\n") : undefined,
          driverMessage: cause && cause.message,
          driverDetail: cause && cause.detail,
          failedQuery: cause && cause.query,
        },
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
    logger.info({ port: PORT }, "graphql api listening");
  });
}

start().catch((err) => {
  logger.error({ err }, "graphql api failed to start");
  process.exit(1);
});
