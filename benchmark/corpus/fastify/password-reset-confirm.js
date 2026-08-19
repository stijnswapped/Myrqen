import crypto from "node:crypto";
import bcrypt from "bcryptjs";

const RESET_WINDOW_MS = 30 * 60 * 1000;
const BCRYPT_ROUNDS = 12;

const requestSchema = {
  body: {
    type: "object",
    required: ["email"],
    additionalProperties: false,
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
    },
  },
};

export default async function (fastify, options) {
  const accounts = fastify.mongo.db.collection("accounts");
  const resetRequests = fastify.mongo.db.collection("password_reset_requests");

  // POST /auth/password-reset/request
  // Always answers 202 so the form cannot be used to enumerate registered addresses.
  fastify.post(
    "/auth/password-reset/request",
    { schema: requestSchema, config: { rateLimit: { max: 5, timeWindow: "10 minutes" } } },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const account = await accounts.findOne({ email }, { projection: { _id: 1 } });

      if (account) {
        const token = crypto.randomBytes(32).toString("hex");
        await resetRequests.insertOne({
          accountId: account._id,
          email,
          token,
          createdAt: new Date(),
          usedAt: null,
        });
        await fastify.mailer.sendResetLink(email, token);
      }

      return reply.code(202).send({ status: "sent" });
    }
  );

  // POST /auth/password-reset/confirm
  // Consumes the emailed token, rotates the password hash and drops every live session.
  fastify.post(
    "/auth/password-reset/confirm",
    { config: { rateLimit: { max: 10, timeWindow: "10 minutes" } } },
    async (request, reply) => {
      const { email, token, password } = request.body;
      const cutoff = new Date(Date.now() - RESET_WINDOW_MS);

      const pending = await resetRequests.findOne({
        email: email,
        token: token,
        usedAt: null,
        createdAt: { $gte: cutoff },
      });

      if (!pending) {
        return reply.code(400).send({ error: "reset_link_expired" });
      }

      if (typeof password !== "string" || password.length < 12) {
        return reply.code(422).send({ error: "password_too_short" });
      }

      const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      await accounts.updateOne(
        { _id: pending.accountId },
        { $set: { passwordHash, passwordChangedAt: new Date() } }
      );
      await resetRequests.updateOne({ _id: pending._id }, { $set: { usedAt: new Date() } });
      await fastify.sessions.revokeAllForAccount(pending.accountId);

      return reply.code(200).send({ status: "updated" });
    }
  );
}
