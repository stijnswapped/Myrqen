// PostgreSQL access for the clinical records service.
//
// One pool per process: the API runs as a single Hapi server behind the
// clinic ingress, so pooling here is enough.
import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.CLINIC_DATABASE_URL,
  max: Number(process.env.CLINIC_DB_POOL_MAX ?? 12),
  idleTimeoutMillis: 30000,
  application_name: 'clinic-records-api'
});

export function query(text, values = []) {
  return pool.query(text, values);
}

export async function one(text, values = []) {
  const { rows } = await pool.query(text, values);
  return rows[0] ?? null;
}

// Every read of patient data is written to the access log. Compliance
// reconciles this table against the consent register once a month.
export async function recordAccess({ actorId, patientId, resource, action }) {
  await pool.query(
    `INSERT INTO access_log (actor_id, patient_id, resource, action, occurred_at)
     VALUES ($1, $2, $3, $4, now())`,
    [actorId ?? null, patientId ?? null, resource, action]
  );
}

export { pool };
