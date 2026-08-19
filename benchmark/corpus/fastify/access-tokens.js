import bcrypt from "bcryptjs";
import rateLimit from "@fastify/rate-limit";
import { randomUUID } from "node:crypto";

const ACCESS_TTL_SECONDS = 60 * 15;

const passwordGrantSchema = {
  body: {
    type: "object",
    required: ["email", "password"],
    additionalProperties: false,
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      password: { type: "string", minLength: 1, maxLength: 200 },
    },
  },
};

const refreshGrantSchema = {
  body: {
    type: "object",
    required: ["refreshToken"],
    additionalProperties: false,
    properties: { refreshToken: { type: "string", pattern: "^[a-f0-9-]{36}$" } },
  },
};

export default async function (fastify, options) {
  const accounts = fastify.mongo.db.collection("accounts");
  const tokens = fastify.mongo.db.collection("api_tokens");

  await fastify.register(rateLimit, { global: false, redis: fastify.redis });

  // POST /auth/tokens
  // Password grant used by the mobile client to exchange credentials for a token pair.
  fastify.post("/auth/tokens", { schema: passwordGrantSchema }, async (request, reply) => {
    const email = request.body.email.trim().toLowerCase();
    const account = await accounts.findOne({ email, status: "active" });

    if (!account || !(await bcrypt.compare(request.body.password, account.passwordHash))) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    const refreshToken = randomUUID();
    await tokens.insertOne({
      _id: refreshToken,
      accountId: account._id,
      createdAt: new Date(),
      revokedAt: null,
    });

    return reply.code(201).send({
      accessToken: await fastify.signAccessToken(account, ACCESS_TTL_SECONDS),
      refreshToken,
      expiresIn: ACCESS_TTL_SECONDS,
    });
  });

  // POST /auth/tokens/refresh
  // Silent renewal; the client calls this whenever the access token nears expiry.
  fastify.post(
    "/auth/tokens/refresh",
    { schema: refreshGrantSchema, config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const stored = await tokens.findOne({ _id: request.body.refreshToken, revokedAt: null });
      const account = stored
        ? await accounts.findOne({ _id: stored.accountId, status: "active" })
        : null;

      if (!account) {
        return reply.code(401).send({ error: "invalid_refresh_token" });
      }

      return reply.send({
        accessToken: await fastify.signAccessToken(account, ACCESS_TTL_SECONDS),
        expiresIn: ACCESS_TTL_SECONDS,
      });
    }
  );

  // DELETE /auth/tokens/:tokenId
  // Sign-out from one device; the token list screen calls this per row.
  fastify.delete(
    "/auth/tokens/:tokenId",
    { preHandler: [fastify.authenticate], config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      await tokens.updateOne(
        { _id: request.params.tokenId, accountId: request.user.accountId },
        { $set: { revokedAt: new Date() } }
      );
      return reply.code(204).send();
    }
  );
}
