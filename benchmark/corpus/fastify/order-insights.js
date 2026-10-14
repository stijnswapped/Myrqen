const STATUSES = ["pending", "paid", "shipped", "refunded"];

export default async function (fastify, options) {
  const orders = fastify.mongo.db.collection("orders");

  // POST /insights/orders
  // Revenue per customer for the insights dashboard. The dashboard posts its
  // filter panel as JSON; only the order status is applied today.
  fastify.post(
    "/insights/orders",
    { preHandler: [fastify.authenticate] },
    async (request, reply) => {
      const { status } = request.body;

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
