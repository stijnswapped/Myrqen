import { Container, CosmosClient, Database } from "@azure/cosmos";
import { DefaultAzureCredential } from "@azure/identity";
import { randomUUID } from "node:crypto";

/**
 * Sitewatch keeps everything in one Cosmos DB SQL-API database.
 *
 * Partition keys, as decided during the 2023 migration off SQL Server:
 *
 *   permits, inspections, assets        -> /siteId
 *   siteMembers, webhooks, exportJobs   -> /tenantId
 *   tenantSettings, auditEvents         -> /tenantId
 *
 * Every document also carries a denormalised tenantId. A site belongs to exactly one
 * customer tenant, so the two are redundant on paper, but nearly every query filters
 * on the tenant and it makes the audit trail self-contained.
 */

const COSMOS_ENDPOINT = process.env.COSMOS_ENDPOINT ?? "";
const COSMOS_DATABASE = process.env.COSMOS_DATABASE ?? "sitewatch";

export type ContainerName =
  | "permits"
  | "inspections"
  | "assets"
  | "siteMembers"
  | "webhooks"
  | "exportJobs"
  | "tenantSettings"
  | "auditEvents";

let cachedDatabase: Database | undefined;

function database(): Database {
  if (!COSMOS_ENDPOINT) {
    throw new Error("COSMOS_ENDPOINT is not configured for this function app");
  }
  if (!cachedDatabase) {
    // Managed identity in Azure, the developer's own identity locally. We deliberately
    // do not keep account keys in app settings any more.
    const client = new CosmosClient({
      endpoint: COSMOS_ENDPOINT,
      aadCredentials: new DefaultAzureCredential(),
      userAgentSuffix: "sitewatch-api",
    });
    cachedDatabase = client.database(COSMOS_DATABASE);
  }
  return cachedDatabase;
}

export function container(name: ContainerName): Container {
  return database().container(name);
}

export interface BaseDocument {
  id: string;
  tenantId: string;
  createdAt: string;
  updatedAt?: string;
  updatedBy?: string;
}

export type PermitStatus = "draft" | "issued" | "suspended" | "closed";

export interface PermitApproval {
  role: string;
  approvedBy: string;
  approvedAt: string;
}

export interface PermitDocument extends BaseDocument {
  siteId: string;
  reference: string;
  workDescription: string;
  status: PermitStatus;
  contractorId: string;
  contractorName: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  plannedStart: string;
  plannedEnd: string;
  hazards: string[];
  notes?: string;
  contactPhone?: string;
  approvals: PermitApproval[];
}

export type InspectionStatus = "scheduled" | "in_progress" | "failed" | "signed_off";

export interface InspectionDocument extends BaseDocument {
  siteId: string;
  permitId: string;
  reference: string;
  status: InspectionStatus;
  inspectorId: string;
  scheduledFor: string;
  findings: string[];
  defectSeverity: "none" | "minor" | "major" | "critical";
  remedialNotes?: string;
  signedOffBy?: string;
  signedOffAt?: string;
}

export interface AssetDocument extends BaseDocument {
  siteId: string;
  assetTag: string;
  description: string;
  status: "in_service" | "quarantined" | "retired";
  installedAt: string;
  nextServiceDue: string;
  ownerContractorId: string;
}

export interface SiteMemberDocument extends BaseDocument {
  siteId: string;
  principalId: string;
  displayName: string;
  role: "SiteViewer" | "SiteSupervisor" | "SiteAdmin";
  invitedBy: string;
}

export interface WebhookDocument extends BaseDocument {
  siteId: string;
  callbackUrl: string;
  events: string[];
  secret: string;
  active: boolean;
  lastDeliveryAt?: string;
  lastDeliveryStatus?: number;
}

export interface ExportJobDocument extends BaseDocument {
  siteId: string;
  status: "queued" | "running" | "complete" | "failed";
  includeSignatures: boolean;
  requestedBy: string;
  downloadPath: string;
}

export interface TenantSettingsDocument extends BaseDocument {
  displayName: string;
  regulatorExportEnabled: boolean;
  verifiedCallbackDomains: string[];
  retentionDays: number;
}

export interface AuditEventInput {
  tenantId: string;
  actorId: string;
  action: string;
  subjectId: string;
  siteId?: string;
  detail?: Record<string, unknown>;
}

/**
 * Audit events are append-only and partitioned by /tenantId. Failing to write one must
 * never take a request down with it, so callers get a resolved promise either way and we
 * rely on the alert on the "audit write failed" log line.
 */
export async function recordAuditEvent(event: AuditEventInput): Promise<void> {
  try {
    await container("auditEvents").items.create({
      id: randomUUID(),
      at: new Date().toISOString(),
      ...event,
    });
  } catch (error) {
    console.error("audit write failed", { action: event.action, error });
  }
}
