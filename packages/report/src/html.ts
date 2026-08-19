import { BRAND } from "@myrqen/brand";
import type { Finding, ReportProjection, ScanReport } from "@myrqen/contracts";
import { buildFixPrompt } from "./fix-prompt.js";
import { formatDuration, formatTokenUsage, sortFindings, verificationLabel } from "./build.js";

/**
 * The renderer accepts either the canonical report or a server-generated viewer
 * projection. Anything absent from the input is absent from the output: the HTML
 * never receives hidden content to filter client-side.
 */
export type ViewableReport = (ScanReport | ReportProjection) & {
  /** Present on projections that withhold content from the current viewer. */
  redactionNotice?: string;
};

export interface RenderOptions {
  /** Shown in the header, for example "Local report" or a viewer label. */
  contextLabel?: string;
  /** Adds a non-alarming banner, used for shared/anonymized views. */
  notice?: string;
  /** Print-oriented layout for PDF export paths. */
  print?: boolean;
  cloudUrl?: string;
  expiresAt?: string;
}

function esc(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character
  );
}

function jsonForScript(value: unknown): string {
  // Escape sequences that would otherwise terminate the script element or break
  // JSON parsing inside HTML.
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

const SEVERITY_GLYPH: Record<Finding["severity"], string> = {
  critical: "◆◆◆",
  high: "◆◆",
  medium: "◆",
  low: "◇",
  info: "·"
};

const VERIFICATION_GLYPH: Record<Finding["verification"], string> = {
  verified: "✓",
  strong_evidence: "≈",
  needs_review: "?"
};

const STYLES = `
:root{
  color-scheme: dark;
  --canvas:#090B0D; --surface:#0E1114; --raised:#13171B; --hover:#181D22;
  --border:#252B31; --borderStrong:#343C44;
  --text:#F3F5F7; --muted:#9AA3AD; --faint:#69737D;
  --brand:#B9F34A; --brandSoft:rgba(185,243,74,.12);
  --critical:#FF5C6C; --high:#FF875C; --medium:#F5C85B; --low:#6FB7FF; --info:#8D98A5;
  --success:#61D998;
  --radius:10px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--canvas)}
body{margin:0;background:var(--canvas);color:var(--text);font:400 14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--text)}
.wrap{max-width:1180px;margin:0 auto;padding:40px 24px 96px}
.skip{position:absolute;left:-9999px}
.skip:focus{left:16px;top:16px;background:var(--brand);color:#0B0D0F;padding:8px 12px;border-radius:6px;z-index:20}
.brandline{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:26px;border-bottom:1px solid var(--border)}
.wordmark{font-weight:800;letter-spacing:.14em;font-size:12px;color:var(--brand)}
.wordmark span{color:var(--faint);letter-spacing:.04em;font-weight:500;margin-left:10px}
.state{font:600 10px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:6px 10px}
.state[data-tone="complete"]{color:var(--brand);border-color:rgba(185,243,74,.34)}
h1{font:600 30px/1.2 var(--sans);letter-spacing:-.02em;margin:26px 0 6px}
.sub{color:var(--muted);margin:0}
.sub b{color:var(--text);font-weight:500}
.notice{margin:22px 0 0;border:1px solid var(--borderStrong);background:var(--raised);border-radius:var(--radius);padding:12px 14px;color:var(--muted);font-size:13px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:8px;margin:26px 0 0}
.metric{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px}
.metric small{display:block;color:var(--muted);font-size:11px;letter-spacing:.02em}
.metric b{display:block;font:600 20px/1.25 var(--sans);margin-top:4px}
.metric b[data-sev="critical"]{color:var(--critical)}
.metric b[data-sev="high"]{color:var(--high)}
.metric b[data-sev="medium"]{color:var(--medium)}
.metric b[data-sev="low"]{color:var(--low)}
.metric b[data-sev="verified"]{color:var(--brand)}
.section{margin-top:44px}
.section > h2{font:600 16px/1.4 var(--sans);margin:0 0 14px;display:flex;align-items:center;gap:10px}
.section > h2 em{font-style:normal;color:var(--faint);font-weight:400;font-size:12px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 16px}
.filters label{font-size:11px;color:var(--faint);letter-spacing:.06em;text-transform:uppercase;margin-right:2px}
.chipbtn{background:var(--surface);border:1px solid var(--border);color:var(--muted);border-radius:999px;padding:6px 11px;font:500 12px/1 var(--sans);cursor:pointer}
.chipbtn[aria-pressed="true"]{background:var(--brandSoft);border-color:rgba(185,243,74,.35);color:var(--text)}
.chipbtn:focus-visible,.copy:focus-visible,summary:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.findings{display:flex;flex-direction:column;gap:10px}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.finding[data-sev="critical"]{border-left:3px solid var(--critical)}
.finding[data-sev="high"]{border-left:3px solid var(--high)}
.finding[data-sev="medium"]{border-left:3px solid var(--medium)}
.finding[data-sev="low"]{border-left:3px solid var(--low)}
.finding[data-sev="info"]{border-left:3px solid var(--info)}
.finding[hidden]{display:none}
summary{list-style:none;cursor:pointer;padding:16px 18px;display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:start}
summary::-webkit-details-marker{display:none}
.finding[open] summary{background:var(--hover);border-bottom:1px solid var(--border)}
.chips{display:flex;flex-direction:column;gap:6px;min-width:104px}
.sev,.ver,.status{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:6px;padding:3px 7px;font:600 10px/1.35 var(--mono);letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
.sev[data-sev="critical"]{color:var(--critical);border-color:rgba(255,92,108,.4)}
.sev[data-sev="high"]{color:var(--high);border-color:rgba(255,135,92,.4)}
.sev[data-sev="medium"]{color:var(--medium);border-color:rgba(245,200,91,.4)}
.sev[data-sev="low"]{color:var(--low);border-color:rgba(111,183,255,.4)}
.sev[data-sev="info"]{color:var(--info)}
.ver{color:var(--muted);font-weight:500;letter-spacing:.04em;text-transform:none}
.ver[data-ver="verified"]{color:var(--brand);border-color:rgba(185,243,74,.32)}
.status{color:var(--success);border-color:rgba(97,217,152,.35);font-weight:500;letter-spacing:.04em;text-transform:none}
.headline h3{font:600 16px/1.4 var(--sans);margin:0 0 4px}
.where{font:400 12px/1.5 var(--mono);color:var(--muted);word-break:break-word}
.oneline{margin:8px 0 0;color:var(--muted);font-size:13px}
.expand{font:500 11px/1 var(--sans);color:var(--faint);white-space:nowrap;padding-top:4px}
.body{padding:6px 18px 22px}
.body h4{font:600 11px/1 var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin:24px 0 8px}
.body p{margin:0 0 10px}
.evidence{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}
.evidence li{border:1px solid var(--border);background:var(--raised);border-radius:var(--radius);padding:12px 14px}
.ekind{font:600 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--brand)}
.evidence p{margin:8px 0 0;color:var(--text)}
.eloc{font:400 11px/1.5 var(--mono);color:var(--faint);margin-top:6px}
.redacted{color:var(--faint);font-size:11px;margin-top:8px;font-style:italic}
pre{margin:10px 0 0;padding:12px 14px;background:#0B0E11;border:1px solid var(--border);border-radius:8px;overflow-x:auto}
code{font:400 12px/1.6 var(--mono)}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:24px;padding-top:18px;border-top:1px solid var(--border)}
.copy{background:var(--brand);color:#0B0D0F;border:0;border-radius:8px;padding:10px 14px;font:700 12px/1 var(--sans);cursor:pointer}
.copy.secondary{background:var(--surface);color:var(--text);border:1px solid var(--borderStrong);font-weight:600}
.hint{color:var(--faint);font-size:11px;align-self:center}
.list{margin:0;padding-left:20px;color:var(--muted)}
.list li{margin:6px 0}
.list li b{color:var(--text);font-weight:500}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
.card h3{font:600 13px/1.4 var(--sans);margin:0 0 8px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:13px;margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
.kv dd.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
.covered{color:var(--success)}
.notcovered{color:var(--medium)}
.empty{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:26px}
.empty b{display:block;font:600 16px/1.4 var(--sans);margin-bottom:6px}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--border);color:var(--faint);font-size:11px;display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(12px);background:var(--raised);border:1px solid var(--borderStrong);border-radius:999px;padding:10px 18px;font-size:12px;opacity:0;pointer-events:none;transition:opacity .16s ease, transform .16s ease}
.toast[data-visible="true"]{opacity:1;transform:translateX(-50%) translateY(0)}
@media (prefers-reduced-motion: reduce){.toast{transition:none}}
@media (max-width:720px){
  .wrap{padding:26px 14px 72px}
  h1{font-size:24px}
  summary{grid-template-columns:1fr;gap:10px}
  .chips{flex-direction:row;min-width:0}
  .expand{display:none}
}
@media print{
  :root{color-scheme:light}
  body{background:#fff;color:#101316}
  .wrap{max-width:none;padding:0}
  .filters,.actions,.toast,.skip{display:none}
  .finding,.metric,.card,.evidence li,pre{border-color:#c9ced4;background:#fff;break-inside:avoid}
  .wordmark{color:#101316}
  .sub,.muted,.where,.oneline{color:#3d454d}
  a[href]::after{content:" (" attr(href) ")";font-size:10px;color:#5b646d}
  @page{margin:16mm}
}
`;

function findingBlock(finding: Finding, index: number, promptAvailable: boolean): string {
  const evidence = [...finding.evidence, ...(finding.corroboration ?? [])];
  const evidenceHtml =
    evidence.length > 0
      ? `<ul class="evidence">${evidence
          .map(
            (item) => `<li>
      <span class="ekind">${esc(item.kind.replaceAll("_", " "))}</span>
      <p>${esc(item.description)}</p>
      ${item.location ? `<div class="eloc">${esc(item.location)}</div>` : ""}
      ${item.snippet ? `<pre><code>${esc(item.snippet)}</code></pre>` : ""}
      ${item.redacted && !item.snippet ? `<div class="redacted">Some detail in this evidence is not shown in this view.</div>` : ""}
    </li>`
          )
          .join("")}</ul>`
      : `<p class="sub">No evidence detail is available in this view.</p>`;

  const where = [finding.affected.route, finding.affected.file, finding.affected.origin]
    .filter(Boolean)
    .join("  ·  ");

  const statusChip =
    finding.status === "fixed_verified"
      ? `<span class="status">Fixed and verified</span>`
      : finding.status === "fix_applied"
        ? `<span class="status">Fix applied, not verified</span>`
        : "";

  return `<details class="finding" id="${esc(finding.id)}" data-sev="${esc(finding.severity)}" data-ver="${esc(finding.verification)}"${index === 0 ? " open" : ""}>
  <summary>
    <div class="chips">
      <span class="sev" data-sev="${esc(finding.severity)}"><span aria-hidden="true">${SEVERITY_GLYPH[finding.severity]}</span>${esc(finding.severity)}</span>
      <span class="ver" data-ver="${esc(finding.verification)}"><span aria-hidden="true">${VERIFICATION_GLYPH[finding.verification]}</span>${esc(verificationLabel(finding.verification))}</span>
      ${statusChip}
    </div>
    <div class="headline">
      <h3>${esc(finding.id)} &middot; ${esc(finding.title)}</h3>
      <div class="where">${esc(where || finding.affected.component)}</div>
      <p class="oneline">${esc(finding.impact)}</p>
    </div>
    <div class="expand">Details</div>
  </summary>
  <div class="body">
    <h4>Root cause</h4>
    <p>${esc(finding.summary)}</p>
    <h4>Affected component</h4>
    <p class="where">${esc(finding.affected.component)}${finding.affected.lineStart ? ` (lines ${finding.affected.lineStart}${finding.affected.lineEnd ? `-${finding.affected.lineEnd}` : ""})` : ""}</p>
    <h4>Evidence</h4>
    ${evidenceHtml}
    ${finding.reproduction ? `<h4>Local reproduction</h4><pre><code>${esc(finding.reproduction)}</code></pre>` : ""}
    <h4>Remediation</h4>
    <p>${esc(finding.remediation)}</p>
    <h4>Verification</h4>
    <p>${esc(finding.verificationPlan)}</p>
    ${
      finding.fixHistory && finding.fixHistory.length > 0
        ? `<h4>Remediation history</h4><ul class="list">${finding.fixHistory
            .map(
              (entry) =>
                `<li><b>${esc(entry.action.replaceAll("_", " "))}</b> — ${esc(entry.at)}${entry.verified ? " · verification passed" : " · not verified"}${entry.note ? ` · ${esc(entry.note)}` : ""}</li>`
            )
            .join("")}</ul>`
        : ""
    }
    ${finding.category || finding.taxonomy?.length ? `<h4>Classification</h4><p class="where">${esc(finding.category)}${finding.taxonomy?.length ? `  ·  ${esc(finding.taxonomy.join(", "))}` : ""}</p>` : ""}
    <div class="actions">
      ${promptAvailable ? `<button class="copy" type="button" data-prompt-for="${esc(finding.id)}">Copy prompt to fix</button>` : ""}
      <button class="copy secondary" type="button" data-copy-text="${esc(`${finding.id} ${finding.title}`)}">Copy finding reference</button>
      <span class="hint">Applying a change is always an explicit action in your coding agent.</span>
    </div>
  </div>
</details>`;
}

function metricsBlock(report: ViewableReport): string {
  const summary = report.summary;
  if (!summary) return "";
  const cells: Array<[string, string, string?]> = [
    ["Critical", String(summary.severityCounts.critical), "critical"],
    ["High", String(summary.severityCounts.high), "high"],
    ["Medium", String(summary.severityCounts.medium), "medium"],
    ["Low", String(summary.severityCounts.low), "low"],
    ["Verified", String(summary.verificationCounts.verified), "verified"],
    ["Findings", String(summary.findingCount)]
  ];
  if (summary.fixedCount !== undefined) cells.push(["Fixed", String(summary.fixedCount)]);
  return `<section class="metrics" aria-label="Finding counts">${cells
    .map(
      ([label, value, tone]) =>
        `<div class="metric"><small>${esc(label)}</small><b${tone ? ` data-sev="${tone}"` : ""}>${esc(value)}</b></div>`
    )
    .join("")}</section>`;
}

function scanCard(report: ViewableReport, options: RenderOptions): string {
  const scan = report.scan;
  if (!scan) return "";
  const rows: Array<[string, string, boolean?]> = [
    ["Effort requested", scan.effortRequested],
    ["Effort resolved", scan.effortResolved],
    ["Host agent", [scan.agent.name, scan.agent.version].filter(Boolean).join(" ") || "unknown"],
    ["Model", scan.agent.model ?? "unknown"],
    ["Duration", formatDuration(scan.durationMs)],
    ["Token usage", formatTokenUsage(scan.tokenUsage)]
  ];
  if (scan.host) {
    rows.push(["Platform", `${scan.host.osFamily} ${scan.host.arch}`]);
    rows.push([
      "Isolated runtime",
      scan.host.isolatedRuntimeAvailable === undefined
        ? "unknown"
        : scan.host.isolatedRuntimeAvailable
          ? "available"
          : "not available on this machine"
    ]);
    if (scan.host.cliVersion) rows.push([`${BRAND.displayName} version`, scan.host.cliVersion]);
  }
  if (scan.stack) {
    if (scan.stack.frameworks.length > 0) rows.push(["Frameworks", scan.stack.frameworks.join(", ")]);
    if (scan.stack.languages.length > 0) rows.push(["Languages", scan.stack.languages.join(", ")]);
  }
  if (options.expiresAt) rows.push(["Cloud copy expires", options.expiresAt]);

  const targets = `<div class="card"><h3>Scope and authorization</h3><dl class="kv">
    <dt>Local targets</dt><dd class="mono">${scan.scope.localTargets.length > 0 ? esc(scan.scope.localTargets.join(", ")) : "none recorded"}</dd>
    <dt>External targets</dt><dd class="mono">${
      scan.scope.externalTargets.length > 0
        ? esc(scan.scope.externalTargets.map((target) => target.target).join(", "))
        : "none authorized"
    }</dd>
    <dt>Destructive actions</dt><dd>not permitted</dd>
    <dt>External authorization</dt><dd>exact origin only</dd>
  </dl>${
    report.authorization?.notes?.length
      ? `<ul class="list">${report.authorization.notes.map((note) => `<li>${esc(note)}</li>`).join("")}</ul>`
      : ""
  }</div>`;

  return `<div class="cards">
    <div class="card"><h3>Scan metadata</h3><dl class="kv">${rows
      .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`)
      .join("")}</dl></div>
    ${targets}
  </div>`;
}

function coverageBlock(report: ViewableReport): string {
  const parts: string[] = [];
  if (report.coverage && report.coverage.length > 0) {
    parts.push(
      `<div class="card"><h3>Assessed</h3><ul class="list">${report.coverage
        .map((line) => `<li>${esc(line)}</li>`)
        .join("")}</ul></div>`
    );
  }
  if (report.coverageAreas && report.coverageAreas.length > 0) {
    parts.push(
      `<div class="card"><h3>Coverage by area</h3><ul class="list">${report.coverageAreas
        .map(
          (area) =>
            `<li><b class="${area.assessed ? "covered" : "notcovered"}">${area.assessed ? "assessed" : "not assessed"}</b> — ${esc(area.area)}${area.method ? ` · ${esc(area.method)}` : ""}${area.note ? ` · ${esc(area.note)}` : ""}</li>`
        )
        .join("")}</ul></div>`
    );
  }
  if (report.limitations && report.limitations.length > 0) {
    parts.push(
      `<div class="card"><h3>Limitations</h3><ul class="list">${report.limitations
        .map((line) => `<li>${esc(line)}</li>`)
        .join("")}</ul></div>`
    );
  }
  if (parts.length === 0) return "";
  return `<section class="section" id="coverage"><h2>Coverage and limitations <em>what was and was not assessed</em></h2><div class="cards">${parts.join("")}</div></section>`;
}

const SCRIPT = `
(function(){
  var prompts = {};
  var node = document.getElementById('myrqen-fix-prompts');
  if (node) { try { prompts = JSON.parse(node.textContent || '{}'); } catch (e) { prompts = {}; } }

  var toast = document.getElementById('toast');
  var toastTimer = null;
  function showToast(message){
    if (!toast) return;
    toast.textContent = message;
    toast.setAttribute('data-visible','true');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ toast.setAttribute('data-visible','false'); }, 1800);
  }

  function copy(text, done){
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function(){ done(true); }, function(){ done(fallback(text)); });
      return;
    }
    done(fallback(text));
  }

  function fallback(text){
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly','');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  document.addEventListener('click', function(event){
    var target = event.target.closest('[data-prompt-for],[data-copy-text]');
    if (!target) return;
    var id = target.getAttribute('data-prompt-for');
    var text = id ? prompts[id] : target.getAttribute('data-copy-text');
    if (!text) { showToast('Nothing to copy'); return; }
    var label = target.textContent;
    copy(text, function(ok){
      target.textContent = ok ? 'Copied' : 'Copy failed';
      showToast(ok ? 'Copied to clipboard' : 'Copy failed. Select the text manually.');
      setTimeout(function(){ target.textContent = label; }, 1400);
    });
  });

  var state = { sev: 'all', ver: 'all' };
  function applyFilters(){
    var findings = document.querySelectorAll('.finding');
    var shown = 0;
    for (var i = 0; i < findings.length; i++) {
      var element = findings[i];
      var okSev = state.sev === 'all' || element.getAttribute('data-sev') === state.sev;
      var okVer = state.ver === 'all' || element.getAttribute('data-ver') === state.ver;
      var visible = okSev && okVer;
      element.hidden = !visible;
      if (visible) shown++;
    }
    var counter = document.getElementById('shown-count');
    if (counter) counter.textContent = String(shown);
    var empty = document.getElementById('filter-empty');
    if (empty) empty.hidden = shown !== 0;
  }

  document.addEventListener('click', function(event){
    var button = event.target.closest('.chipbtn');
    if (!button) return;
    var group = button.getAttribute('data-group');
    var value = button.getAttribute('data-value');
    if (!group || !value) return;
    state[group] = value;
    var peers = document.querySelectorAll('.chipbtn[data-group="' + group + '"]');
    for (var i = 0; i < peers.length; i++) peers[i].setAttribute('aria-pressed', String(peers[i] === button));
    applyFilters();
  });

  applyFilters();
})();
`;

/**
 * Self-contained offline HTML. No network requests, no external fonts, no
 * trackers: everything needed to read the report is in this one file.
 */
export function renderStandaloneHtml(report: ViewableReport, options: RenderOptions = {}): string {
  const findings = sortFindings(report.findings ?? []);
  const canonical = report as ScanReport;
  const promptAvailable = Boolean(report.findings);
  const prompts: Record<string, string> = {};
  if (promptAvailable) {
    for (const finding of findings) {
      const context: { projectName?: string; localReportId?: string } = { localReportId: report.id };
      if (report.project?.name) context.projectName = report.project.name;
      prompts[finding.id] = buildFixPrompt(finding, context);
    }
  }

  const projectName = report.project?.name ?? `${BRAND.displayName} report`;
  const stateLabel = options.contextLabel ?? "Local report";
  const generated = report.generatedAt ? new Date(report.generatedAt).toISOString().replace("T", " ").slice(0, 16) : "";
  const subline = [
    report.project?.workspaceName ? `${report.project.workspaceName} workspace` : null,
    report.scan ? `${report.scan.effortRequested} effort` : null,
    report.scan?.agent.name ?? null,
    report.scan ? formatDuration(report.scan.durationMs) : null,
    generated ? `generated ${generated} UTC` : null
  ]
    .filter(Boolean)
    .join("  ·  ");

  const severityFilters = ["all", "critical", "high", "medium", "low", "info"];
  const verificationFilters = ["all", "verified", "strong_evidence", "needs_review"];

  const findingsSection =
    findings.length > 0
      ? `<section class="section" id="findings">
    <h2>Findings <em><span id="shown-count">${findings.length}</span> shown of ${findings.length}</em></h2>
    <div class="filters" role="group" aria-label="Filter findings">
      <label>Severity</label>
      ${severityFilters
        .map(
          (value) =>
            `<button class="chipbtn" type="button" data-group="sev" data-value="${value}" aria-pressed="${value === "all"}">${value === "all" ? "All" : esc(value)}</button>`
        )
        .join("")}
      <label style="margin-left:12px">Verification</label>
      ${verificationFilters
        .map(
          (value) =>
            `<button class="chipbtn" type="button" data-group="ver" data-value="${value}" aria-pressed="${value === "all"}">${value === "all" ? "All" : esc(verificationLabel(value as Finding["verification"]))}</button>`
        )
        .join("")}
    </div>
    <div class="findings">${findings.map((finding, index) => findingBlock(finding, index, promptAvailable)).join("")}</div>
    <div class="empty" id="filter-empty" hidden><b>No findings match these filters</b><p class="sub">Clear a filter to see the rest of the report.</p></div>
  </section>`
      : `<section class="section" id="findings"><h2>Findings</h2><div class="empty"><b>No findings were reported</b><p class="sub">This is not evidence that the application is secure. Read the coverage and limitations below to see what was assessed.</p></div></section>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>${esc(BRAND.displayName)} report — ${esc(projectName)}</title>
<style>${STYLES}</style>
</head>
<body>
<a class="skip" href="#findings">Skip to findings</a>
<div class="wrap">
  <header>
    <div class="brandline">
      <div class="wordmark">${esc(BRAND.uppercaseName)}<span>authorized application security assessment</span></div>
      <div class="state" data-tone="complete">${esc(stateLabel)}</div>
    </div>
    <h1>${esc(projectName)}</h1>
    <p class="sub">${esc(subline)}</p>
    ${options.notice ? `<p class="notice">${esc(options.notice)}</p>` : ""}
    ${report.redactionNotice ? `<p class="notice">${esc(report.redactionNotice)}</p>` : ""}
    ${metricsBlock(report)}
  </header>

  ${findingsSection}

  ${report.scan ? `<section class="section" id="metadata"><h2>Scan and scope <em>how this assessment ran</em></h2>${scanCard(report, options)}</section>` : ""}

  ${coverageBlock(report)}

  ${
    canonical.methodologyVersion
      ? `<section class="section"><h2>Methodology <em>version ${esc(canonical.methodologyVersion)}</em></h2>
    <div class="card"><ul class="list">
      <li>Preflight and authorization boundaries, then application mapping.</li>
      <li>Source, configuration, and dependency review for plausible root causes.</li>
      <li>Controlled dynamic validation against authorized targets only.</li>
      <li>Access-control comparison across the available test identities.</li>
      <li>Validation, deduplication, and a false-positive challenge pass.</li>
      <li>Remediation guidance with a targeted verification step per finding.</li>
    </ul></div></section>`
      : ""
  }

  <footer>
    <span>${esc(BRAND.reportFooter)}</span>
    <span>Report ${esc(report.id)} · schema ${esc(report.schemaVersion ?? BRAND.reportSchemaVersion)}${options.cloudUrl ? ` · ${esc(options.cloudUrl)}` : ""}</span>
  </footer>
</div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script type="application/json" id="myrqen-fix-prompts">${jsonForScript(prompts)}</script>
<script>${SCRIPT}</script>
</body>
</html>
`;
}
