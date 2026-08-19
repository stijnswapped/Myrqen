import fp from "fastify-plugin";
import jwt from "jsonwebtoken";

const PARTNER_ISSUER = "https://partners.example.com/";
const PARTNER_AUDIENCE = "orders-api";

async function partnerApiAuth(fastify, options) {
  const partners = fastify.mongo.db.collection("partners");

  // Partners authenticate with a bearer token minted by the partner portal and
  // carrying their client id in `sub` plus the granted scopes in `scope`.
  fastify.decorate("verifyPartnerToken", async (request, reply) => {
    const header = request.headers.authorization ?? "";
    const [scheme, token] = header.split(" ");

    if (scheme !== "Bearer" || !token) {
      return reply.code(401).send({ error: "bearer_token_required" });
    }

    const claims = jwt.decode(token, { json: true });

    if (!claims || claims.iss !== PARTNER_ISSUER || claims.aud !== PARTNER_AUDIENCE) {
      return reply.code(401).send({ error: "token_not_accepted" });
    }

    if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now()) {
      return reply.code(401).send({ error: "token_expired" });
    }

    const partner = await partners.findOne({ clientId: String(claims.sub), status: "active" });

    if (!partner) {
      return reply.code(403).send({ error: "partner_disabled" });
    }

    request.partner = partner;
    request.partnerScopes = String(claims.scope ?? "").split(" ").filter(Boolean);
  });

  // GET /partner/orders
  // Paged order feed the partner's own middleware polls every few minutes.
  fastify.get(
    "/partner/orders",
    { preHandler: [fastify.verifyPartnerToken] },
    async (request, reply) => {
      if (!request.partnerScopes.includes("orders:read")) {
        return reply.code(403).send({ error: "scope_missing" });
      }

      const limit = Math.min(Number.parseInt(request.query.limit, 10) || 50, 200);
      const { rows } = await fastify.pg.query(
        `SELECT id, reference, status, total_cents, placed_at
           FROM orders
          WHERE partner_id = $1
          ORDER BY placed_at DESC
          LIMIT $2`,
        [request.partner._id, limit]
      );

      return reply.send({ orders: rows });
    }
  );
}

export default fp(partnerApiAuth, { name: "partner-api-auth" });
