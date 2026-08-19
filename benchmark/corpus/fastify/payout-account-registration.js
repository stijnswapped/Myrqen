import { randomUUID } from "node:crypto";

const bankAccountSchema = {
  body: {
    type: "object",
    required: ["iban", "accountHolder", "country"],
    additionalProperties: false,
    properties: {
      iban: { type: "string", pattern: "^[A-Z]{2}[0-9A-Z]{13,32}$" },
      accountHolder: { type: "string", minLength: 2, maxLength: 120 },
      country: { type: "string", pattern: "^[A-Z]{2}$" },
      makeDefault: { type: "boolean", default: false },
    },
  },
};

export default async function (fastify, options) {
  const payoutAccounts = fastify.mongo.db.collection("payout_accounts");

  // POST /billing/payout-accounts
  // Adds a bank account for payouts. The IBAN is exchanged for a processor token and
  // only the token, bank name and last four digits are persisted.
  fastify.post(
    "/billing/payout-accounts",
    { preHandler: [fastify.authenticate], schema: bankAccountSchema },
    async (request, reply) => {
      const correlationId = randomUUID();

      // Support quotes the correlation id back to us when the processor rejects an
      // account, so log it together with the fields that identify the submission.
      request.log.info(
        {
          correlationId,
          accountId: request.user.accountId,
          country: request.body.country,
          ibanLast4: request.body.iban.slice(-4),
        },
        "payout account registration received"
      );

      const tokenised = await fastify.processor.tokeniseBankAccount({
        iban: request.body.iban,
        holder: request.body.accountHolder,
        country: request.body.country,
        idempotencyKey: correlationId,
      });

      if (!tokenised.approved) {
        return reply.code(402).send({ error: "account_rejected", reason: tokenised.rejectCode });
      }

      const stored = {
        _id: randomUUID(),
        accountId: request.user.accountId,
        processorToken: tokenised.token,
        bankName: tokenised.bankName,
        last4: request.body.iban.slice(-4),
        country: request.body.country,
        createdAt: new Date(),
      };

      await payoutAccounts.insertOne(stored);

      if (request.body.makeDefault) {
        await payoutAccounts.updateMany(
          { accountId: request.user.accountId, _id: { $ne: stored._id } },
          { $set: { isDefault: false } }
        );
        await payoutAccounts.updateOne({ _id: stored._id }, { $set: { isDefault: true } });
      }

      return reply.code(201).send({
        id: stored._id,
        bankName: stored.bankName,
        last4: stored.last4,
        isDefault: Boolean(request.body.makeDefault),
      });
    }
  );
}
