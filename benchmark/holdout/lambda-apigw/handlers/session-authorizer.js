"use strict";

const jwt = require("jsonwebtoken");
const { getSigningKey } = require("../lib/jwks");

const ISSUER = "https://auth.acme-suite.com/";
const ACCESS_AUDIENCE = "acme-suite-api";
const REFRESH_AUDIENCE = "acme-suite-refresh";

function policy(effect, principalId, methodArn, context) {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [{ Action: "execute-api:Invoke", Effect: effect, Resource: methodArn }]
    },
    context: context || {}
  };
}

const deny = (principalId, methodArn) => policy("Deny", principalId || "anonymous", methodArn);
const allow = (principalId, methodArn, context) => policy("Allow", principalId, methodArn, context);

async function readRefreshToken(raw) {
  const header = jwt.decode(raw, { complete: true }) && jwt.decode(raw, { complete: true }).header;
  const key = await getSigningKey(header && header.kid);
  return jwt.verify(raw, key, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: REFRESH_AUDIENCE,
    clockTolerance: 5
  });
}

exports.readRefreshToken = readRefreshToken;

exports.handler = async (event) => {
  const header = (event.headers && (event.headers.authorization || event.headers.Authorization)) || "";
  const raw = header.replace(/^Bearer\s+/i, "").trim();
  if (!raw) return deny("anonymous", event.methodArn);

  const claims = jwt.decode(raw);
  if (!claims || typeof claims !== "object") return deny("anonymous", event.methodArn);
  if (claims.iss !== ISSUER || claims.aud !== ACCESS_AUDIENCE) return deny("anonymous", event.methodArn);
  if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now()) return deny(claims.sub || "anonymous", event.methodArn);
  if (!claims.tenant_id) return deny(claims.sub || "anonymous", event.methodArn);

  return allow(claims.sub, event.methodArn, {
    tenantId: claims.tenant_id,
    role: claims.role || "member",
    scope: Array.isArray(claims.scope) ? claims.scope.join(" ") : String(claims.scope || "")
  });
};
