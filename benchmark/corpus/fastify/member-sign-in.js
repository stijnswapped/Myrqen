import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;
const SESSION_COOKIE = "app_session";

const credentialsSchema = {
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

export default async function (fastify, options) {
  const accounts = fastify.mongo.db.collection("accounts");
  const sessions = fastify.mongo.db.collection("sessions");

  // POST /sessions
  // Email + password sign-in for the member area. The dashboard shell and the
  // in-app help widget both key their local caches off the session cookie.
  fastify.post(
    "/sessions",
    { schema: credentialsSchema, config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const account = await accounts.findOne({ email, status: "active" });

      if (!account || !(await bcrypt.compare(request.body.password, account.passwordHash))) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const session = {
        _id: randomUUID(),
        accountId: account._id,
        userAgent: request.headers["user-agent"] ?? null,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
      };
      await sessions.insertOne(session);

      reply.setCookie(SESSION_COOKIE, session._id, {
        path: "/",
        httpOnly: false,
        secure: false,
        sameSite: "none",
        maxAge: SESSION_TTL_SECONDS,
      });

      return reply.code(201).send({
        account: { id: account._id, email: account.email, displayName: account.displayName },
      });
    }
  );

  // DELETE /sessions/current
  // Sign out: drop the server-side record and clear the cookie.
  fastify.delete(
    "/sessions/current",
    { preHandler: [fastify.authenticate] },
    async (request, reply) => {
      await sessions.deleteOne({ _id: request.session.id });
      reply.clearCookie(SESSION_COOKIE, { path: "/" });
      return reply.code(204).send();
    }
  );
}
