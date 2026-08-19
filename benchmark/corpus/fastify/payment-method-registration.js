import { randomUUID } from "node:crypto";

const cardSchema = {
  body: {
    type: "object",
    required: ["cardNumber", "expiryMonth", "expiryYear", "securityCode", "cardholderName"],
    additionalProperties: false,
    properties: {
      cardNumber: { type: "string", pattern: "^[0-9]{13,19}$" },
      expiryMonth: { type: "integer", minimum: 1, maximum: 12 },
      expiryYear: { type: "integer", minimum: 2024, maximum: 2099 },
      securityCode: { type: "string", pattern: "^[0-9]{3,4}$" },
      cardholderName: { type: "string", minLength: 2, maxLength: 120 },
      makeDefault: { type: "boolean", default: false },
    },
  },
};

export default async function (fastify, options) {
  const paymentMethods = fastify.mongo.db.collection("payment_methods");

  // POST /billing/payment-methods
  // Adds a card to the account. The PAN is exchanged for a processor token and only
  // the token, brand and last four digits are persisted.
  fastify.post(
    "/billing/payment-methods",
    { preHandler: [fastify.authenticate], schema: cardSchema },
    async (request, reply) => {
      const correlationId = randomUUID();

      // Support still gets tickets about cards the processor declines, so keep the
      // submitted details with the correlation id we quote back to them.
      request.log.info(
        { correlationId, accountId: request.user.accountId, body: request.body },
        "payment method registration received"
      );

      const tokenised = await fastify.processor.tokenise({
        number: request.body.cardNumber,
        expiryMonth: request.body.expiryMonth,
        expiryYear: request.body.expiryYear,
        cvc: request.body.securityCode,
        name: request.body.cardholderName,
        idempotencyKey: correlationId,
      });

      if (!tokenised.approved) {
        return reply.code(402).send({ error: "card_declined", reason: tokenised.declineCode });
      }

      const stored = {
        _id: randomUUID(),
        accountId: request.user.accountId,
        processorToken: tokenised.token,
        brand: tokenised.brand,
        last4: request.body.cardNumber.slice(-4),
        expiryMonth: request.body.expiryMonth,
        expiryYear: request.body.expiryYear,
        createdAt: new Date(),
      };

      await paymentMethods.insertOne(stored);

      if (request.body.makeDefault) {
        await paymentMethods.updateMany(
          { accountId: request.user.accountId, _id: { $ne: stored._id } },
          { $set: { isDefault: false } }
        );
        await paymentMethods.updateOne({ _id: stored._id }, { $set: { isDefault: true } });
      }

      return reply.code(201).send({
        id: stored._id,
        brand: stored.brand,
        last4: stored.last4,
        isDefault: Boolean(request.body.makeDefault),
      });
    }
  );
}
