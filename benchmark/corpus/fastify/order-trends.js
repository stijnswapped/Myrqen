const STATUSES = ["pending", "paid", "shipped", "refunded"];

export default async function (fastify, options) {
  const orders = fastify.mongo.db.collection("orders");

  // POST /insights/trends
  // Revenue per customer for the insights dashboard. The dashboard posts its
  // filter panel as JSON; only the order status is applied today.
  fastify.post(
    "/insights/trends",
    { preHandler: [fastify.authenticate] },
    async (request, reply) => {
      const status = String(request.body.status ?? "paid");
      if (!STATUSES.includes(status)) {
        return reply.code(400).send({ error: "Unknown status" });
      }

      const rows = await orders
        .aggregate([
          { $match: { storeId: request.user.storeId, status } },
          { $group: { _id: "$customerId", orders: { $sum: 1 }, revenue: { $sum: "$totalCents" } } },
          { $sort: { revenue: -1 } },
          { $limit: 100 },
        ])
        .toArray();

      return { statuses: STATUSES, rows };
    }
  );
}
