import ajv2020Module from "ajv/dist/2020.js";
import type { ErrorObject, ValidateFunction } from "ajv/dist/2020.js";
import ajvFormatsModule from "ajv-formats";

/**
 * ajv and ajv-formats are CommonJS. Under NodeNext the default export can be
 * wrapped depending on the consumer, so unwrap defensively instead of assuming.
 */
type Ajv2020Ctor = new (options?: Record<string, unknown>) => Ajv2020Instance;
interface Ajv2020Instance {
  compile(schema: object): ValidateFunction;
  addSchema(schema: object): unknown;
  getSchema(ref: string): ValidateFunction | undefined;
}
type FormatsPlugin = (ajv: Ajv2020Instance) => unknown;

function unwrap<T>(mod: unknown): T {
  const candidate = mod as { default?: unknown };
  if (candidate && typeof candidate === "object" && "default" in candidate && candidate.default) {
    return candidate.default as T;
  }
  return mod as T;
}

const Ajv2020 = unwrap<Ajv2020Ctor>(ajv2020Module);
const addFormats = unwrap<FormatsPlugin>(ajvFormatsModule);
import {
  FINDING_SCHEMA,
  FINDING_SUBMISSION_SCHEMA,
  PROJECT_BINDING_SCHEMA,
  REPORT_SCHEMA,
  SCAN_EVENT_SCHEMA,
  SHARE_POLICY_SCHEMA,
  UPDATE_MANIFEST_SCHEMA
} from "./generated-schemas.js";
import type { Finding, SafeScanEvent, ScanReport } from "./domain.js";
import type { FindingSubmission } from "./agent-protocol.js";
import type { ProjectionPolicy } from "./share.js";

export interface ValidationIssue {
  path: string;
  message: string;
  keyword: string;
}

export interface ValidationResult<T> {
  valid: boolean;
  value?: T;
  issues: ValidationIssue[];
}

function buildAjv(): Ajv2020Instance {
  const instance = new Ajv2020({ allErrors: true, strict: false, allowUnionTypes: true });
  addFormats(instance);
  // The report schema references the finding schema by $id.
  instance.addSchema(FINDING_SCHEMA as unknown as object);
  return instance;
}

const ajv = buildAjv();

function compile(schema: unknown): ValidateFunction {
  return ajv.compile(schema as object);
}

const validators = {
  report: compile(REPORT_SCHEMA),
  findingSubmission: compile(FINDING_SUBMISSION_SCHEMA),
  scanEvent: compile(SCAN_EVENT_SCHEMA),
  sharePolicy: compile(SHARE_POLICY_SCHEMA),
  projectBinding: compile(PROJECT_BINDING_SCHEMA),
  updateManifest: compile(UPDATE_MANIFEST_SCHEMA)
} as const;

const findingValidator = ajv.getSchema("https://schemas.myrqen.invalid/finding.schema.json");
if (!findingValidator) throw new Error("Finding schema failed to register.");

function toIssues(errors: ErrorObject[] | null | undefined): ValidationIssue[] {
  return (errors ?? []).map((error) => ({
    path: error.instancePath || "/",
    message: describe(error),
    keyword: error.keyword
  }));
}

function describe(error: ErrorObject): string {
  if (error.keyword === "additionalProperties") {
    const extra = (error.params as { additionalProperty?: string }).additionalProperty;
    return `unexpected field "${extra}" is not allowed`;
  }
  if (error.keyword === "required") {
    const missing = (error.params as { missingProperty?: string }).missingProperty;
    return `missing required field "${missing}"`;
  }
  return error.message ?? "invalid value";
}

function run<T>(validate: ValidateFunction, value: unknown): ValidationResult<T> {
  const valid = validate(value) as boolean;
  if (valid) return { valid: true, value: value as T, issues: [] };
  return { valid: false, issues: toIssues(validate.errors) };
}

export const validateReport = (value: unknown): ValidationResult<ScanReport> =>
  run<ScanReport>(validators.report, value);
export const validateFinding = (value: unknown): ValidationResult<Finding> =>
  run<Finding>(findingValidator, value);
export const validateFindingSubmission = (value: unknown): ValidationResult<FindingSubmission> =>
  run<FindingSubmission>(validators.findingSubmission, value);
export const validateScanEvent = (value: unknown): ValidationResult<SafeScanEvent> =>
  run<SafeScanEvent>(validators.scanEvent, value);
export const validateSharePolicy = (value: unknown): ValidationResult<ProjectionPolicy> =>
  run<ProjectionPolicy>(validators.sharePolicy, value);
export const validateProjectBinding = (value: unknown): ValidationResult<unknown> =>
  run<unknown>(validators.projectBinding, value);
export const validateUpdateManifest = (value: unknown): ValidationResult<unknown> =>
  run<unknown>(validators.updateManifest, value);

export function formatIssues(issues: ValidationIssue[], limit = 12): string {
  if (issues.length === 0) return "";
  const shown = issues.slice(0, limit).map((issue) => `  ${issue.path} ${issue.message}`);
  const rest = issues.length > limit ? [`  ...and ${issues.length - limit} more`] : [];
  return [...shown, ...rest].join("\n");
}
