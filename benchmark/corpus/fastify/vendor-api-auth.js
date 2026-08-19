import fp from "fastify-plugin";
import jwt from "jsonwebtoken";

const VENDOR_ISSUER = "https://vendors.example.com/";
const VENDOR_AUDIENCE = "shipments-api";
const VENDOR_PUBLIC_KEY = process.env.VENDOR_JWT_PUBLIC_KEY;

async function vendorApiAuth(fastify, options) {
  const vendors = fastify.mongo.db.collection("vendors");

  // Vendors authenticate with a bearer token minted by the vendor portal and
  // carrying their client id in `sub` plus the granted scopes in `scope`.
  fastify.decorate("verifyVendorToken", async (request, reply) => {
    const header = request.headers.authorization ?? "";
    const [scheme, token] = header.split(" ");

    if (scheme !== "Bearer" || !token) {
      return reply.code(401).send({ error: "bearer_token_required" });
    }

    let claims;
    try {
      claims = jwt.verify(token, VENDOR_PUBLIC_KEY, {
        algorithms: ["RS256"],
        issuer: VENDOR_ISSUER,
        audience: VENDOR_AUDIENCE,
        clockTolerance: 5,
      });
    } catch (err) {
      return reply.code(401).send({ error: "token_not_accepted" });
    }

    const vendor = await vendors.findOne({ clientId: String(claims.sub), status: "active" });

    if (!vendor) {
      return reply.code(403).send({ error: "vendor_disabled" });
    }

    request.vendor = vendor;
    request.vendorScopes = String(claims.scope ?? "").split(" ").filter(Boolean);
  });

  // GET /vendor/shipments
  // Paged shipment feed the vendor's own middleware polls every few minutes.
  fastify.get(
    "/vendor/shipments",
    { preHandler: [fastify.verifyVendorToken] },
    async (request, reply) => {
      if (!request.vendorScopes.includes("shipments:read")) {
        return reply.code(403).send({ error: "scope_missing" });
      }

      const limit = Math.min(Number.parseInt(request.query.limit, 10) || 50, 200);
      const { rows } = await fastify.pg.query(
        `SELECT id, tracking_code, status, dispatched_at
           FROM shipments
          WHERE vendor_id = $1
          ORDER BY dispatched_at DESC
          LIMIT $2`,
        [request.vendor._id, limit]
      );

      return reply.send({ shipments: rows });
    }
  );
}

export default fp(vendorApiAuth, { name: "vendor-api-auth" });
