import { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";

const url = Deno.env.get("DATABASE_URL");
if (!url) throw new Error("DATABASE_URL is required");

export const pool = new Pool(url, 8, true);
