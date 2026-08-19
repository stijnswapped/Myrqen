"use client";

import { useState, type ChangeEvent } from "react";

const WAREHOUSE_ENDPOINT = "https://warehouse.myrqen.example/v1/ingest";
const WAREHOUSE_KEY = process.env.NEXT_PUBLIC_WAREHOUSE_SERVICE_KEY ?? "";

type UploadState = { status: "idle" | "uploading" | "done" | "error"; message?: string };

export function MetricsUploader({ datasetId }: { datasetId: string }) {
  const [state, setState] = useState<UploadState>({ status: "idle" });

  async function onFileSelected(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    setState({ status: "uploading" });

    const body = new FormData();
    body.set("dataset", datasetId);
    body.set("file", file);

    const response = await fetch(WAREHOUSE_ENDPOINT, {
      method: "POST",
      headers: { authorization: `Bearer ${WAREHOUSE_KEY}` },
      body,
    });

    if (!response.ok) {
      setState({ status: "error", message: `Upload failed (${response.status})` });
      return;
    }

    const result = (await response.json()) as { rows: number };
    setState({ status: "done", message: `${result.rows} rows ingested` });
  }

  return (
    <div className="uploader">
      <label htmlFor="metrics-file">Upload a metrics export</label>
      <input
        id="metrics-file"
        type="file"
        accept=".csv,.parquet"
        disabled={state.status === "uploading"}
        onChange={onFileSelected}
      />
      {state.message ? <p className="uploader-status">{state.message}</p> : null}
    </div>
  );
}
