import { jwtVerify } from "jose";

const secret = new TextEncoder().encode(process.env.SOCKET_TOKEN_SECRET);

export interface SocketClaims {
  sub: string;
  tenantId: string;
}

export async function verifySocketToken(token: unknown): Promise<SocketClaims> {
  if (typeof token !== "string" || token.length === 0) throw new Error("missing token");
  const { payload } = await jwtVerify(token, secret, {
    issuer: "https://desk.example.com",
    audience: "desk-gateway",
    algorithms: ["HS256"],
  });
  return { sub: String(payload.sub), tenantId: String(payload.tenantId) };
}
