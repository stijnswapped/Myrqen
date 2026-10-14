import { SQL } from "bun";

const client = new SQL(Bun.env.DATABASE_URL!);

export async function sql<T>(text: string, values: unknown[] = []): Promise<T[]> {
  return (await client.unsafe(text, values)) as T[];
}
