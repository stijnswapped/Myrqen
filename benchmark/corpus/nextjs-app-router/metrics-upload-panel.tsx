import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { datasets } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { mintWarehouseUploadToken } from "@/lib/warehouse";
import { DatasetUploader } from "./dataset-uploader";

const UPLOAD_TOKEN_TTL_SECONDS = 300;

export default async function MetricsUploadPanel({ datasetId }: { datasetId: string }) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    redirect("/sign-in");
  }

  const dataset = await db.query.datasets.findFirst({
    where: eq(datasets.id, datasetId),
    columns: { id: true, name: true, organizationId: true },
  });

  if (!dataset || dataset.organizationId !== session.organizationId) {
    return <p className="empty">That dataset is not available.</p>;
  }

  const uploadToken = await mintWarehouseUploadToken({
    serviceKey: process.env.WAREHOUSE_SERVICE_KEY,
    datasetId: dataset.id,
    organizationId: session.organizationId,
    scope: "ingest:append",
    ttlSeconds: UPLOAD_TOKEN_TTL_SECONDS,
  });

  return (
    <section className="upload-panel">
      <h2>{dataset.name}</h2>
      <p className="hint">CSV or Parquet, up to 200 MB per file.</p>
      <DatasetUploader datasetId={dataset.id} uploadToken={uploadToken} />
    </section>
  );
}
