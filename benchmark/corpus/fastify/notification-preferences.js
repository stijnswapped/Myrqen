const CHANNELS = ["email", "push", "sms"];

const preferencesSchema = {
  body: {
    type: "object",
    required: ["channels"],
    additionalProperties: false,
    properties: {
      channels: {
        type: "array",
        items: { type: "string", enum: CHANNELS },
        uniqueItems: true,
      },
      digestHour: { type: "integer", minimum: 0, maximum: 23 },
      quietWeekends: { type: "boolean", default: false },
    },
  },
};

export default async function (fastify, options) {
  // GET /users/:userId/notification-preferences
  // Populates the notifications tab in account settings.
  fastify.get(
    "/users/:userId/notification-preferences",
    { preHandler: [fastify.authenticate, fastify.requireSelf] },
    async (request, reply) => {
      const { rows } = await fastify.pg.query(
        `SELECT channels, digest_hour, quiet_weekends, updated_at
           FROM notification_preferences
          WHERE user_id = $1`,
        [request.params.userId]
      );

      return reply.send({ preferences: rows[0] ?? { channels: ["email"], digest_hour: 8 } });
    }
  );

  // PUT /users/:userId/notification-preferences
  // Saves the notifications tab; the form posts the whole set on every change.
  fastify.put(
    "/users/:userId/notification-preferences",
    { schema: preferencesSchema },
    async (request, reply) => {
      const { channels, digestHour = 8, quietWeekends = false } = request.body;

      const { rows } = await fastify.pg.query(
        `INSERT INTO notification_preferences (user_id, channels, digest_hour, quiet_weekends, updated_at)
              VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (user_id) DO UPDATE
                 SET channels = EXCLUDED.channels,
                     digest_hour = EXCLUDED.digest_hour,
                     quiet_weekends = EXCLUDED.quiet_weekends,
                     updated_at = now()
           RETURNING channels, digest_hour, quiet_weekends, updated_at`,
        [request.params.userId, channels, digestHour, quietWeekends]
      );

      return reply.send({ preferences: rows[0] });
    }
  );

  // DELETE /users/:userId/notification-preferences
  // "Reset to defaults" link under the form.
  fastify.delete(
    "/users/:userId/notification-preferences",
    { preHandler: [fastify.authenticate, fastify.requireSelf] },
    async (request, reply) => {
      await fastify.pg.query(`DELETE FROM notification_preferences WHERE user_id = $1`, [
        request.params.userId,
      ]);

      return reply.code(204).send();
    }
  );
}
