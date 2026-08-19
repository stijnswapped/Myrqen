const TOPICS = ["product_updates", "billing", "security", "research_invites"];

const preferencesSchema = {
  body: {
    type: "object",
    required: ["topics"],
    additionalProperties: false,
    properties: {
      topics: {
        type: "array",
        items: { type: "string", enum: TOPICS },
        uniqueItems: true,
      },
      locale: { type: "string", pattern: "^[a-z]{2}(-[A-Z]{2})?$" },
      marketingOptIn: { type: "boolean", default: false },
    },
  },
};

export default async function (fastify, options) {
  // GET /users/:userId/communication-preferences
  // Populates the email preferences tab in account settings.
  fastify.get(
    "/users/:userId/communication-preferences",
    { preHandler: [fastify.authenticate, fastify.requireSelf] },
    async (request, reply) => {
      const { rows } = await fastify.pg.query(
        `SELECT topics, locale, marketing_opt_in, updated_at
           FROM communication_preferences
          WHERE user_id = $1`,
        [request.user.accountId]
      );

      return reply.send({ preferences: rows[0] ?? { topics: ["security"], locale: "en" } });
    }
  );

  // PUT /users/:userId/communication-preferences
  // Saves the email preferences tab; the form posts the whole set on every change.
  fastify.put(
    "/users/:userId/communication-preferences",
    { preHandler: [fastify.authenticate, fastify.requireSelf], schema: preferencesSchema },
    async (request, reply) => {
      const { topics, locale = "en", marketingOptIn = false } = request.body;

      const { rows } = await fastify.pg.query(
        `INSERT INTO communication_preferences (user_id, topics, locale, marketing_opt_in, updated_at)
              VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (user_id) DO UPDATE
                 SET topics = EXCLUDED.topics,
                     locale = EXCLUDED.locale,
                     marketing_opt_in = EXCLUDED.marketing_opt_in,
                     updated_at = now()
           RETURNING topics, locale, marketing_opt_in, updated_at`,
        [request.user.accountId, topics, locale, marketingOptIn]
      );

      return reply.send({ preferences: rows[0] });
    }
  );

  // DELETE /users/:userId/communication-preferences
  // "Reset to defaults" link under the form.
  fastify.delete(
    "/users/:userId/communication-preferences",
    { preHandler: [fastify.authenticate, fastify.requireSelf] },
    async (request, reply) => {
      await fastify.pg.query(`DELETE FROM communication_preferences WHERE user_id = $1`, [
        request.user.accountId,
      ]);

      return reply.code(204).send();
    }
  );
}
