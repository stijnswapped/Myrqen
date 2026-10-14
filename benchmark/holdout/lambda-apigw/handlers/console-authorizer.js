"use strict";

const jwt = require("jsonwebtoken");
const { getSigningKey } = require("../lib/jwks");

const ISSUER = "https://auth.acme-suite.com/";
const CONSOLE_AUDIENCE = "acme-suite-console";
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

async function verify(raw, audience) {
  const decoded = jwt.decode(raw, { complete: true });
  const key = await getSigningKey(decoded && decoded.header && decoded.header.kid);
  return jwt.verify(raw, key, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience,
    clockTolerance: 5
  });
}

exports.readRefreshToken = (raw) => verify(raw, REFRESH_AUDIENCE);

exports.handler = async (event) => {
  const header = (event.headers && (event.headers.authorization || event.headers.Authorization)) || "";
  const raw = header.replace(/^Bearer\s+/i, "").trim();
  if (!raw) return deny("anonymous", event.methodArn);

  let claims;
  try {
    claims = await verify(raw, CONSOLE_AUDIENCE);
  } catch (err) {
    return deny("anonymous", event.methodArn);
  }
  if (!claims.tenant_id) return deny(claims.sub || "anonymous", event.methodArn);

  return allow(claims.sub, event.methodArn, {
    tenantId: claims.tenant_id,
    role: claims.role || "member",
    scope: Array.isArray(claims.scope) ? claims.scope.join(" ") : String(claims.scope || "")
  });
};
