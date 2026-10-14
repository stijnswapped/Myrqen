import { BadRequestException, Body, Controller, Post, UseGuards } from "@nestjs/common";
import { exec, execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { RolesGuard } from "../auth/roles.guard";
import { Roles } from "../auth/roles.decorator";

const shell = promisify(exec);
const spawnBinary = promisify(execFile);

const CONVERTER = "/usr/bin/soffice";
const CONVERT_TIMEOUT_MS = 30_000;
const OUTPUT_FORMATS = ["pdf", "xlsx", "html"];

interface ExportRequest {
  rows: Array<Record<string, string | number>>;
  filename: string;
  format: string;
}

function toCsv(rows: Array<Record<string, string | number>>): string {
  if (rows.length === 0) return "";
  const columns = Object.keys(rows[0]);
  const escapeCell = (value: string | number) => `"${String(value).replace(/"/g, '""')}"`;
  return [columns.join(","), ...rows.map((row) => columns.map((c) => escapeCell(row[c])).join(","))].join("\n");
}

@Roles("analyst", "manager")
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller("reports")
export class ReportExportController {
  @Post("archive")
  async archive(@Body() body: ExportRequest) {
    const workdir = await mkdtemp(join(tmpdir(), "report-"));
    const source = join(workdir, `${randomUUID()}.csv`);
    await writeFile(source, toCsv(body.rows), "utf8");
    const { stdout } = await spawnBinary("/usr/bin/zip", ["-j", "-q", `${source}.zip`, source]);
    return { archive: `${source}.zip`, log: stdout.trim() };
  }

  @Post("export")
  async export(@Body() body: ExportRequest) {
    if (!OUTPUT_FORMATS.includes(body.format)) throw new BadRequestException("unsupported output format");
    if (!body.filename) throw new BadRequestException("a filename is required");

    const workdir = await mkdtemp(join(tmpdir(), "report-"));
    const source = join(workdir, `${randomUUID()}.csv`);
    await writeFile(source, toCsv(body.rows), "utf8");

    const destination = join(workdir, body.filename);
    const converted = `${workdir}/*.${body.format}`;
    const pipeline = `${CONVERTER} --headless --convert-to ${body.format} --outdir ${workdir} ${source} && mv ${converted} ${destination}`;

    const { stderr } = await shell(pipeline, { timeout: CONVERT_TIMEOUT_MS });
    if (stderr.trim().length > 0) throw new BadRequestException("conversion failed");
    return { path: destination, format: body.format };
  }
}
