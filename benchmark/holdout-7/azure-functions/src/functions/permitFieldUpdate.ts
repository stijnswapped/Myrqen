import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, resolveSiteMembership, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { PermitDocument, container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * Permit edit from the tablet app. Supervisors correct the free-text parts of a permit all
 * day long. Anything that changes the state of the permit - issuing it, suspending it,
 * signing off an approval - goes through the approvals endpoints instead, because those
 * need a second pair of eyes and a signature.
 *
 * PATCH /api/permits/{permitId}
 */

interface PermitPatchEnvelope {
  siteId?: string;
  patch?: Record<string, unknown>;
}

type EditableField = "workDescription" | "notes" | "contactPhone" | "plannedEnd" | "hazards";

const FIELD_PARSERS: Record<EditableField, (value: unknown) => unknown> = {
  workDescription: (value) => requireText(value, 4, 2000),
  notes: (value) => requireText(value, 0, 4000),
  contactPhone: (value) => requirePhone(value),
  plannedEnd: (value) => requireIsoDate(value),
  hazards: (value) => requireTagList(value),
};

class FieldError extends Error {}

function requireText(value: unknown, min: number, max: number): string {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw new FieldError(`expected text between ${min} and ${max} characters`);
  }
  return value;
}

function requirePhone(value: unknown): string {
  if (typeof value !== "string" || !/^\+?[0-9 ()-]{6,24}$/.test(value)) {
    throw new FieldError("expected a phone number");
  }
  return value;
}

function requireIsoDate(value: unknown): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new FieldError("expected an ISO 8601 timestamp");
  }
  return new Date(value).toISOString();
}

function requireTagList(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new FieldError("expected an array of hazard tags");
  }
  return (value as string[]).slice(0, 25);
}

function isEditable(field: string): field is EditableField {
  return Object.prototype.hasOwnProperty.call(FIELD_PARSERS, field);
}

export async function permitFieldUpdate(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const permitId = request.params.permitId;
  const envelope = (await request.json().catch(() => null)) as PermitPatchEnvelope | null;
  if (!permitId || !envelope?.siteId || !envelope.patch) {
    return { status: 400, jsonBody: { error: "siteId and patch are both required" } };
  }

  try {
    const membership = await resolveSiteMembership(caller.tid, envelope.siteId, caller.oid);
    if (!membership) {
      return { status: 403, jsonBody: { error: "You have no access to that site" } };
    }
    if (membership.role === "SiteViewer") {
      return { status: 403, jsonBody: { error: "Viewers cannot edit permits" } };
    }

    const { resource: existing } = await container("permits")
      .item(permitId, envelope.siteId)
      .read<PermitDocument>();
    if (!existing || existing.tenantId !== caller.tid) {
      return { status: 404, jsonBody: { error: "Permit not found" } };
    }

    // Walk our own list of editable fields rather than the keys of the payload, so a client
    // that sends status, approvals, tenantId or siteId simply does not get them applied -
    // and say so, rather than pretending the write happened.
    const changes: Record<string, unknown> = {};
    const rejected: string[] = [];
    for (const [field, value] of Object.entries(envelope.patch)) {
      if (!isEditable(field)) {
        rejected.push(field);
        continue;
      }
      try {
        changes[field] = FIELD_PARSERS[field](value);
      } catch (fieldError) {
        const reason = fieldError instanceof FieldError ? fieldError.message : "invalid value";
        return { status: 400, jsonBody: { error: `${field}: ${reason}` } };
      }
    }
    if (rejected.length > 0) {
      return { status: 400, jsonBody: { error: `fields cannot be edited here: ${rejected.join(", ")}` } };
    }
    if (Object.keys(changes).length === 0) {
      return { status: 400, jsonBody: { error: "nothing to update" } };
    }

    const updated: PermitDocument = {
      ...existing,
      ...changes,
      updatedAt: new Date().toISOString(),
      updatedBy: caller.oid,
    };
    await container("permits").item(permitId, envelope.siteId).replace<PermitDocument>(updated);

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "permit.updated",
      subjectId: permitId,
      siteId: envelope.siteId,
      detail: { fields: Object.keys(changes) },
    });

    context.log(`permit ${permitId} patched by ${caller.oid} (${Object.keys(changes).join(", ")})`);

    return { status: 200, jsonBody: { id: permitId, updatedAt: updated.updatedAt } };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("permitFieldUpdate", {
  methods: ["PATCH"],
  authLevel: "function",
  route: "api/permits/{permitId}",
  handler: permitFieldUpdate,
});
