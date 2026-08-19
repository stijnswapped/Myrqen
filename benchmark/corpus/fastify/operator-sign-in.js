import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";

const SESSION_TTL_SECONDS = 60 * 60 * 8;
const SESSION_COOKIE = "operator_session";

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
  const operators = fastify.mongo.db.collection("operators");
  const sessions = fastify.mongo.db.collection("operator_sessions");

  // POST /operator/sessions
  // Sign-in for the back-office console. Shift length caps the session lifetime.
  fastify.post(
    "/operator/sessions",
    { schema: credentialsSchema, config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const email = request.body.email.trim().toLowerCase();
      const operator = await operators.findOne({ email, status: "active" });

      if (!operator || !(await bcrypt.compare(request.body.password, operator.passwordHash))) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const session = {
        _id: randomUUID(),
        operatorId: operator._id,
        userAgent: request.headers["user-agent"] ?? null,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
      };
      await sessions.insertOne(session);

      reply.setCookie(SESSION_COOKIE, session._id, {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        signed: true,
        maxAge: SESSION_TTL_SECONDS,
      });

      return reply.code(201).send({
        operator: { id: operator._id, email: operator.email, displayName: operator.displayName },
      });
    }
  );

  // DELETE /operator/sessions/current
  // Sign out: drop the server-side record and clear the cookie.
  fastify.delete(
    "/operator/sessions/current",
    { preHandler: [fastify.authenticate] },
    async (request, reply) => {
      await sessions.deleteOne({ _id: request.session.id });
      reply.clearCookie(SESSION_COOKIE, { path: "/" });
      return reply.code(204).send();
    }
  );
}
