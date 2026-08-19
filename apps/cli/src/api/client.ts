import os from "node:os";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type {
  ApiError,
  ApiErrorCode,
  CreateDeviceLinkRequest,
  CreateDeviceLinkResponse,
  CreateProjectRequest,
  CreateReportRequest,
  CreateReportResponse,
  DeviceLinkStatusResponse,
  ExchangeDeviceLinkResponse,
  FinalizeReportRequest,
  FinalizeReportResponse,
  ProgressRequest,
  ProgressResponse,
  SafeScanEvent,
  SyncQuota,
  UploadIntentResponse,
  WorkspaceSummary
} from "@myrqen/contracts";
import type { ProductEventEnvelope } from "@myrqen/analytics";
import { readCredential } from "../config/credentials.js";
import { readConfig } from "../config/store.js";

export class ApiRequestError extends Error {
  readonly code: ApiErrorCode | "NETWORK" | "MALFORMED";
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(input: {
    code: ApiErrorCode | "NETWORK" | "MALFORMED";
    message: string;
    status: number;
    details?: Record<string, unknown>;
  }) {
    super(input.message);
    this.name = "ApiRequestError";
    this.code = input.code;
    this.status = input.status;
    if (input.details) this.details = input.details;
  }
}

export interface ApiClientOptions {
  baseUrl: string;
  deviceToken?: string;
  timeoutMs?: number;
}

export function userAgent(): string {
  return `${BRAND.userAgentProduct}/${CLI_VERSION} (${process.platform}; ${process.arch}; node ${process.versions.node})`;
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly deviceToken?: string;
  private readonly timeoutMs: number;

  constructor(options: ApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    if (options.deviceToken) this.deviceToken = options.deviceToken;
    this.timeoutMs = options.timeoutMs ?? 20_000;
  }

  get url(): string {
    return this.baseUrl;
  }

  get authenticated(): boolean {
    return Boolean(this.deviceToken);
  }

  private async request<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    const headers: Record<string, string> = { "user-agent": userAgent(), accept: "application/json", ...extraHeaders };
    if (body !== undefined && !headers["content-type"]) headers["content-type"] = "application/json";
    if (this.deviceToken) headers.authorization = `Bearer ${this.deviceToken}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        signal: controller.signal,
        ...(body === undefined
          ? {}
          : { body: body instanceof Buffer ? new Uint8Array(body) : JSON.stringify(body) })
      });
    } catch (error) {
      throw new ApiRequestError({
        code: "NETWORK",
        status: 0,
        message: `Could not reach ${this.baseUrl}: ${error instanceof Error ? error.message : "network error"}`
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    if (!response.ok) {
      let parsed: ApiError | null = null;
      try {
        parsed = JSON.parse(text) as ApiError;
      } catch {
        parsed = null;
      }
      throw new ApiRequestError({
        code: parsed?.error?.code ?? "MALFORMED",
        status: response.status,
        message: parsed?.error?.message ?? `Request failed with status ${response.status}.`,
        ...(parsed?.error?.details ? { details: parsed.error.details } : {})
      });
    }

    if (text.length === 0) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ApiRequestError({ code: "MALFORMED", status: response.status, message: "The server returned an unreadable response." });
    }
  }

  createDeviceLink(body: CreateDeviceLinkRequest): Promise<CreateDeviceLinkResponse> {
    return this.request("POST", "/api/v1/device-links", body);
  }

  deviceLinkStatus(publicRequestId: string): Promise<DeviceLinkStatusResponse> {
    return this.request("GET", `/api/v1/device-links/${encodeURIComponent(publicRequestId)}/status`);
  }

  exchangeDeviceLink(publicRequestId: string, verifier: string): Promise<ExchangeDeviceLinkResponse> {
    return this.request("POST", `/api/v1/device-links/${encodeURIComponent(publicRequestId)}/exchange`, { verifier });
  }

  workspaces(): Promise<{ workspaces: WorkspaceSummary[] }> {
    return this.request("GET", "/api/v1/workspaces");
  }

  createProject(body: CreateProjectRequest): Promise<{ projectId: string; created: boolean }> {
    return this.request("POST", "/api/v1/projects", body);
  }

  syncQuota(workspaceId?: string): Promise<SyncQuota> {
    const query = workspaceId ? `?workspaceId=${encodeURIComponent(workspaceId)}` : "";
    return this.request("GET", `/api/v1/sync-quota${query}`);
  }

  createReport(body: CreateReportRequest): Promise<CreateReportResponse> {
    return this.request("POST", "/api/v1/reports", body);
  }

  sendProgress(reportId: string, events: SafeScanEvent[]): Promise<ProgressResponse> {
    const body: ProgressRequest = { events };
    return this.request("POST", `/api/v1/reports/${encodeURIComponent(reportId)}/progress`, body);
  }

  uploadIntent(reportId: string, sha256: string, byteLength: number): Promise<UploadIntentResponse> {
    return this.request("POST", `/api/v1/reports/${encodeURIComponent(reportId)}/upload-intent`, { sha256, byteLength });
  }

  async uploadBody(uploadUrl: string, body: Buffer): Promise<void> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "user-agent": userAgent()
    };
    if (this.deviceToken) headers.authorization = `Bearer ${this.deviceToken}`;
    const response = await fetch(uploadUrl, { method: "PUT", headers, body: new Uint8Array(body) });
    if (!response.ok) {
      const text = await response.text();
      let parsed: ApiError | null = null;
      try {
        parsed = JSON.parse(text) as ApiError;
      } catch {
        parsed = null;
      }
      throw new ApiRequestError({
        code: parsed?.error?.code ?? "MALFORMED",
        status: response.status,
        message: parsed?.error?.message ?? `Report upload failed with status ${response.status}.`
      });
    }
  }

  finalizeReport(reportId: string, body: FinalizeReportRequest): Promise<FinalizeReportResponse> {
    return this.request("POST", `/api/v1/reports/${encodeURIComponent(reportId)}/finalize`, body);
  }

  sendAnalytics(events: ProductEventEnvelope[]): Promise<{ accepted: number }> {
    return this.request("POST", "/api/v1/analytics/events", { events });
  }

  updateManifest(): Promise<unknown> {
    return this.request("GET", "/api/v1/updates/manifest");
  }
}

export interface ResolvedClient {
  client: ApiClient;
  account?: { userId: string; email: string; deviceId: string; deviceName: string };
  credentialBackend?: string;
}

/** Builds a client from stored config plus the OS-held device credential. */
export async function resolveClient(): Promise<ResolvedClient> {
  const config = await readConfig();
  if (!config.account) return { client: new ApiClient({ baseUrl: config.apiBaseUrl }) };
  const credential = await readCredential(config.account.userId);
  const client = new ApiClient({
    baseUrl: config.apiBaseUrl,
    ...(credential ? { deviceToken: credential.deviceToken } : {})
  });
  return {
    client,
    account: {
      userId: config.account.userId,
      email: config.account.email,
      deviceId: config.account.deviceId,
      deviceName: config.account.deviceName
    },
    ...(credential ? { credentialBackend: credential.backend } : {})
  };
}

export function defaultDeviceName(): string {
  const host = os.hostname().split(".")[0] ?? "device";
  return `${host} (${process.platform === "darwin" ? "macOS" : process.platform})`;
}
