import type { ColumnType, Generated } from "kysely";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

/**
 * Types for the applicant tracking database.
 *
 * Kept in sync by hand with the SQL files in db/migrations — if you add a
 * column in a migration, add it here in the same PR or the builder will happily
 * compile a statement that Postgres rejects at runtime.
 */

export type Timestamp = ColumnType<Date, Date | string, Date | string>;

export type UserRole = "recruiter" | "hiring_manager" | "interviewer" | "admin";

export interface UsersTable {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: Generated<Timestamp>;
}

export interface RequisitionsTable {
  id: string;
  reference: string;
  title: string;
  department: string;
  location: string;
  employment_type: string;
  description_html: string;
  status: "draft" | "open" | "on_hold" | "closed";
  owner_user_id: string;
  salary_band_min: number;
  salary_band_max: number;
  headcount: number;
  is_published: boolean;
  created_at: Generated<Timestamp>;
}

export interface HiringTeamMembersTable {
  id: Generated<string>;
  requisition_id: string;
  user_id: string;
  team_role: "recruiter" | "hiring_manager" | "interviewer" | "coordinator";
  created_at: Generated<Timestamp>;
}

export interface CandidatesTable {
  id: string;
  full_name: string;
  email: string;
  phone: string | null;
  headline: string | null;
  current_employer: string | null;
  expected_salary: number | null;
  internal_rating: number | null;
  national_id_last4: string | null;
  source: string;
  owner_user_id: string | null;
  stage: "new" | "screening" | "interviewing" | "offer" | "hired" | "rejected";
  recruiter_notes: string | null;
  created_at: Generated<Timestamp>;
  updated_at: Timestamp;
}

export interface ApplicationsTable {
  id: string;
  requisition_id: string;
  candidate_id: string;
  status:
    | "submitted"
    | "in_review"
    | "interviewing"
    | "offered"
    | "hired"
    | "rejected"
    | "withdrawn";
  cover_letter_html: string | null;
  cover_letter_text: string | null;
  tracking_token: string;
  referrer_email: string | null;
  decline_reason: string | null;
  submitted_at: Generated<Timestamp>;
}

export interface AttachmentsTable {
  id: string;
  candidate_id: string | null;
  application_id: string | null;
  kind: "cv" | "portfolio" | "offer_letter";
  storage_key: string;
  original_filename: string;
  content_type: string;
  byte_size: number;
  uploaded_at: Generated<Timestamp>;
}

export interface ScorecardsTable {
  id: string;
  application_id: string;
  interviewer_user_id: string;
  competency: string;
  rating: number;
  verdict: "strong_no" | "no" | "yes" | "strong_yes" | null;
  notes: string | null;
  is_submitted: boolean;
  submitted_at: Timestamp | null;
}

export interface OffersTable {
  id: string;
  application_id: string;
  requisition_id: string;
  base_salary: number;
  equity_units: number | null;
  start_date: string;
  letter_attachment_id: string | null;
  status: "draft" | "approved" | "sent" | "accepted" | "declined";
  approved_by_user_id: string | null;
  created_at: Generated<Timestamp>;
}

export interface Database {
  users: UsersTable;
  requisitions: RequisitionsTable;
  hiring_team_members: HiringTeamMembersTable;
  candidates: CandidatesTable;
  applications: ApplicationsTable;
  attachments: AttachmentsTable;
  scorecards: ScorecardsTable;
  offers: OffersTable;
}

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL is required to boot the ATS server");
}

export const db = new Kysely<Database>({
  dialect: new PostgresDialect({
    pool: new Pool({
      connectionString,
      max: Number(process.env.PGPOOL_MAX ?? 10),
      idleTimeoutMillis: 30_000,
      application_name: "ats-web",
    }),
  }),
});
