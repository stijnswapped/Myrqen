import crypto from "node:crypto";
import bcrypt from "bcryptjs";

const INVITE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const BCRYPT_ROUNDS = 12;

const redeemSchema = {
  body: {
    type: "object",
    required: ["email", "token", "password"],
    additionalProperties: false,
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      token: { type: "string", pattern: "^[a-f0-9]{64}$" },
      password: { type: "string", minLength: 12, maxLength: 200 },
    },
  },
};

function matchesToken(candidate, stored) {
  const a = Buffer.from(candidate, "utf8");
  const b = Buffer.from(stored, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export default async function (fastify, options) {
  const accounts = fastify.mongo.db.collection("accounts");
  const invitations = fastify.mongo.db.collection("invitations");

  // POST /auth/invitations/redeem
  // Turns a pending invitation into a real account with a password of its own.
  fastify.post(
    "/auth/invitations/redeem",
    { schema: redeemSchema, config: { rateLimit: { max: 10, timeWindow: "10 minutes" } } },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const token = request.body.token;
      const cutoff = new Date(Date.now() - INVITE_WINDOW_MS);

      const pending = await invitations.findOne({
        email: email,
        token: token,
        acceptedAt: null,
        createdAt: { $gte: cutoff },
      });

      if (!pending || !matchesToken(token, pending.token)) {
        return reply.code(400).send({ error: "invitation_expired" });
      }

      const passwordHash = await bcrypt.hash(request.body.password, BCRYPT_ROUNDS);
      const created = await accounts.insertOne({
        email,
        passwordHash,
        workspaceId: pending.workspaceId,
        role: pending.role,
        createdAt: new Date(),
      });

      await invitations.updateOne(
        { _id: pending._id },
        { $set: { acceptedAt: new Date(), accountId: created.insertedId } }
      );

      return reply.code(201).send({ accountId: created.insertedId, workspaceId: pending.workspaceId });
    }
  );
}
