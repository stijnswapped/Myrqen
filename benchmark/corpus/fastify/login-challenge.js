import crypto from "node:crypto";
import rateLimit from "@fastify/rate-limit";

const CODE_TTL_MS = 10 * 60 * 1000;

const startSchema = {
  body: {
    type: "object",
    required: ["email"],
    additionalProperties: false,
    properties: { email: { type: "string", format: "email", maxLength: 254 } },
  },
};

const completeSchema = {
  body: {
    type: "object",
    required: ["email", "code"],
    additionalProperties: false,
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      code: { type: "string", pattern: "^[0-9]{6}$" },
    },
  },
};

function perAddressAndAccount(request) {
  const email = String(request.body?.email ?? "").trim().toLowerCase();
  return `${request.ip}:${email}`;
}

export default async function (fastify, options) {
  const accounts = fastify.mongo.db.collection("accounts");
  const challenges = fastify.mongo.db.collection("login_challenges");

  await fastify.register(rateLimit, { global: false, redis: fastify.redis });

  // POST /auth/login-challenge
  // Emails a six digit code; the response never reveals whether the address exists.
  fastify.post(
    "/auth/login-challenge",
    {
      schema: startSchema,
      config: { rateLimit: { max: 5, timeWindow: "15 minutes", keyGenerator: perAddressAndAccount } },
    },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const account = await accounts.findOne({ email, status: "active" }, { projection: { _id: 1 } });

      if (account) {
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
        await challenges.insertOne({
          accountId: account._id,
          email,
          codeHash: crypto.createHash("sha256").update(code).digest("hex"),
          createdAt: new Date(),
          usedAt: null,
        });
        await fastify.mailer.sendLoginCode(email, code);
      }

      return reply.code(202).send({ status: "sent" });
    }
  );

  // POST /auth/login-challenge/complete
  // Exchanges a valid code for a session.
  fastify.post(
    "/auth/login-challenge/complete",
    {
      schema: completeSchema,
      config: { rateLimit: { max: 5, timeWindow: "15 minutes", keyGenerator: perAddressAndAccount } },
    },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const codeHash = crypto.createHash("sha256").update(request.body.code).digest("hex");

      const challenge = await challenges.findOne({
        email,
        codeHash,
        usedAt: null,
        createdAt: { $gte: new Date(Date.now() - CODE_TTL_MS) },
      });

      if (!challenge) {
        return reply.code(401).send({ error: "invalid_code" });
      }

      await challenges.updateOne({ _id: challenge._id }, { $set: { usedAt: new Date() } });
      const session = await fastify.sessions.create(challenge.accountId, request);

      return reply.code(201).send({ sessionId: session.id, expiresAt: session.expiresAt });
    }
  );
}
