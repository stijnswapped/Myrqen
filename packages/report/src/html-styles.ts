/**
 * The standalone report's stylesheet.
 *
 * The palette is monochrome with one accent. Green (#4ade5a) means exactly one
 * thing anywhere it appears: verified, or passed. Severity is carried by glyph,
 * weight, and tone of grey — never by a hue — so a reader never has to learn a
 * colour code, a colour-blind reader loses nothing, and the green keeps its meaning.
 *
 * Dark is the default because that is how the product looks; a reader whose system
 * asks for light gets light, and print is always black on white. Every text pairing
 * below meets WCAG AA (4.5:1) against the surface it sits on; the green is only ever
 * used as text on the dark surfaces, where it passes, and as a darker ink of the same
 * hue on light ones.
 */
export const REPORT_STYLES = `
:root{
  color-scheme: dark;
  --canvas:#0A0A0A; --surface:#111111; --raised:#171717; --hover:#1D1D1D;
  --border:#262626; --borderStrong:#3A3A3A;
  --text:#F5F5F5; --muted:#B5B5B5; --faint:#8F8F8F;
  --ok:#4ade5a; --okInk:#4ade5a; --okSoft:rgba(74,222,90,.12); --okLine:rgba(74,222,90,.42);
  --focus:#F5F5F5; --flagBg:rgba(255,255,255,.07);
  --sev-critical:#FFFFFF; --sev-high:#D4D4D4; --sev-medium:#9E9E9E; --sev-low:#6B6B6B; --sev-info:#454545;
  --hatch:rgba(10,10,10,.6);
  --radius:10px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: light){
  :root{
    color-scheme: light;
    --canvas:#FFFFFF; --surface:#FAFAFA; --raised:#F3F3F3; --hover:#EDEDED;
    --border:#E2E2E2; --borderStrong:#C8C8C8;
    --text:#0A0A0A; --muted:#4D4D4D; --faint:#666666;
    --okInk:#17752A; --okSoft:rgba(74,222,90,.16); --okLine:rgba(23,117,42,.45);
    --focus:#0A0A0A; --flagBg:rgba(0,0,0,.05);
    --sev-critical:#0A0A0A; --sev-high:#333333; --sev-medium:#5E5E5E; --sev-low:#8C8C8C; --sev-info:#BDBDBD;
    --hatch:rgba(255,255,255,.65);
  }
}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--canvas)}
body{margin:0;background:var(--canvas);color:var(--text);font:400 14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--text)}
a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
h1,h2,h3,h4{overflow-wrap:anywhere}
.page{max-width:1240px;margin:0 auto;padding:36px 24px 96px}
.skip{position:absolute;left:-9999px}
.skip:focus{left:16px;top:16px;background:var(--text);color:var(--canvas);padding:8px 12px;border-radius:6px;z-index:30}
.sr{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}

/* Header ---------------------------------------------------------- */
.brandline{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px 16px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.wordmark{font-weight:800;letter-spacing:.14em;font-size:12px;color:var(--text)}
.wordmark span{display:inline-block;color:var(--faint);letter-spacing:.04em;font-weight:500;margin-left:10px}
.state{font:600 10px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:6px 10px}
h1{font:600 30px/1.2 var(--sans);letter-spacing:-.02em;margin:24px 0 6px}
.sub{color:var(--muted);margin:0;overflow-wrap:anywhere}
.notice{margin:20px 0 0;border:1px solid var(--borderStrong);background:var(--raised);border-radius:var(--radius);padding:12px 14px;color:var(--muted);font-size:13px}

/* Shell and in-page navigation ------------------------------------ */
.shell{display:block;margin-top:8px}
.toc{display:none}
.main{min-width:0}
@media (min-width:1100px){
  .shell{display:grid;grid-template-columns:200px minmax(0,1fr);gap:48px;align-items:start}
  .toc{display:block;position:sticky;top:24px;max-height:calc(100vh - 48px);overflow:auto;padding-top:40px}
}
.toc ol{list-style:none;margin:0;padding:0;border-left:1px solid var(--border)}
.toc a{display:block;padding:7px 0 7px 14px;margin-left:-1px;border-left:2px solid transparent;color:var(--muted);text-decoration:none;font-size:12.5px;line-height:1.35}
.toc a:hover{color:var(--text)}
.toc a[aria-current="true"]{color:var(--text);border-left-color:var(--text)}
.toc .n{color:var(--faint);font:400 11px/1 var(--mono);margin-left:6px}

/* Sections --------------------------------------------------------- */
.section{margin-top:48px;scroll-margin-top:24px}
.section:first-child{margin-top:36px}
.section > h2{font:600 18px/1.35 var(--sans);letter-spacing:-.01em;margin:0 0 6px}
.section > .say{color:var(--muted);margin:0 0 18px;max-width:78ch}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:10px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;min-width:0}
.card h3{font:600 13px/1.4 var(--sans);margin:0 0 10px}
.list{margin:0;padding-left:20px;color:var(--muted)}
.list li{margin:6px 0;overflow-wrap:anywhere}
.list li b{color:var(--text);font-weight:500}
.kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 16px;font-size:13px;margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;overflow-wrap:anywhere}
.kv dd.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
.kv dd[data-tone="none"]{color:var(--muted);font-style:italic}
.covered{color:var(--okInk)}
.notcovered{color:var(--text);text-decoration:underline dotted;text-underline-offset:3px}

/* Verdict ---------------------------------------------------------- */
.verdict{background:var(--surface);border:1px solid var(--borderStrong);border-radius:14px;padding:26px 28px 24px}
.verdict[data-tone="verified_risk"]{border-color:var(--text);box-shadow:inset 4px 0 0 var(--text)}
.verdict[data-tone="unverified_risk"]{border-style:dashed}
.verdict[data-tone="settled"]{border-color:var(--okLine);box-shadow:inset 4px 0 0 var(--ok)}
.eyebrow{font:600 10.5px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin:0 0 12px;display:flex;align-items:center;gap:10px}
.eyebrow .runmode{color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:4px 8px;letter-spacing:.08em}
.verdict > h2{font:650 24px/1.3 var(--sans);letter-spacing:-.015em;margin:0;max-width:44ch}
.verdict-detail{margin:10px 0 0;color:var(--muted);max-width:80ch}
.verdict-next{margin:18px 0 0;padding:12px 14px;border:1px solid var(--borderStrong);border-radius:8px;background:var(--raised);max-width:80ch}
.verdict-next b{display:block;font:600 10.5px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
.verdict-next code{font:600 13px/1 var(--mono);background:var(--canvas);border:1px solid var(--border);border-radius:5px;padding:2px 6px}
.verdict > h3{font:600 11px/1.3 var(--sans);letter-spacing:.11em;text-transform:uppercase;color:var(--faint);margin:26px 0 10px}
.fixfirst{list-style:none;counter-reset:ff;margin:0;padding:0;display:grid;gap:10px}
.fixfirst li{counter-increment:ff;position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 16px;align-items:start;background:var(--canvas);border:1px solid var(--border);border-radius:10px;padding:14px 16px 14px 52px;min-width:0}
.fixfirst li::before{content:counter(ff);position:absolute;left:16px;top:14px;width:24px;height:24px;border-radius:50%;border:1px solid var(--borderStrong);display:grid;place-items:center;font:600 12px/1 var(--mono);color:var(--text)}
.fixfirst .marks{grid-column:1/-1}
.ff-title{font:600 15px/1.4 var(--sans);text-decoration:none;overflow-wrap:anywhere}
.ff-title:hover{text-decoration:underline;text-underline-offset:3px}
.ff-title .fid{color:var(--faint);font:500 12.5px/1 var(--mono);margin-right:8px;white-space:nowrap}
.fixfirst .where{margin-top:4px}
.why{margin:6px 0 0;color:var(--muted);font-size:13px;max-width:72ch}
.fixfirst .copy{align-self:center}
.caveat{margin:20px 0 0;padding-top:14px;border-top:1px solid var(--border);color:var(--muted);font-size:12.5px;max-width:86ch}
.verdict .empty-ff{margin:14px 0 0;color:var(--muted)}

/* Overview --------------------------------------------------------- */
.summary{max-width:78ch}
.summary p{margin:0 0 14px;color:var(--muted)}
.summary p.lede{font:400 16px/1.62 var(--sans);color:var(--text)}
.stats{display:grid;gap:10px;grid-template-columns:1fr;margin-top:26px}
@media (min-width:860px){.stats{grid-template-columns:1fr 1fr}}
.bar{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--raised);margin:14px 0 12px;border:1px solid var(--border)}
.seg{display:block;min-width:2px}
.seg + .seg{box-shadow:inset 1px 0 0 var(--canvas)}
.seg[data-sev="critical"],.dot[data-sev="critical"]{background:var(--sev-critical)}
.seg[data-sev="high"],.dot[data-sev="high"]{background:var(--sev-high)}
.seg[data-sev="medium"],.dot[data-sev="medium"]{background:var(--sev-medium)}
.seg[data-sev="low"],.dot[data-sev="low"]{background:var(--sev-low)}
.seg[data-sev="info"],.dot[data-sev="info"]{background:var(--sev-info)}
.seg[data-ver="verified"],.dot[data-ver="verified"]{background:var(--ok)}
.seg[data-ver="strong_evidence"]{background:repeating-linear-gradient(115deg,var(--sev-high),var(--sev-high) 3px,var(--hatch) 3px,var(--hatch) 6px)}
.seg[data-ver="needs_review"]{background:repeating-linear-gradient(115deg,var(--sev-low),var(--sev-low) 2px,var(--hatch) 2px,var(--hatch) 6px)}
.barkey{list-style:none;display:flex;flex-wrap:wrap;gap:6px 18px;margin:0;padding:0;font-size:12.5px;color:var(--muted)}
.barkey li{display:flex;align-items:center;gap:7px}
.barkey b{color:var(--text);font-weight:600}
.dot{width:9px;height:9px;border-radius:2px;flex:0 0 auto;border:1px solid var(--borderStrong)}
.dot[data-ver="strong_evidence"]{background:repeating-linear-gradient(115deg,var(--sev-high),var(--sev-high) 2px,var(--hatch) 2px,var(--hatch) 4px)}
.dot[data-ver="needs_review"]{background:repeating-linear-gradient(115deg,var(--sev-low),var(--sev-low) 1px,var(--hatch) 1px,var(--hatch) 3px)}
.numbers{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,128px),1fr));gap:8px;margin-top:10px}
.num{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;min-width:0}
.num small{display:block;color:var(--muted);font-size:11px;letter-spacing:.02em}
.num b{display:block;font:600 22px/1.25 var(--sans);margin-top:4px;font-variant-numeric:tabular-nums}
.num b[data-tone="verified"]{color:var(--okInk)}
.num b[data-tone="zero-verified"]{color:var(--muted)}
.mismatch{margin:12px 0 0;color:var(--muted);font-size:12.5px}

/* Toolbar ---------------------------------------------------------- */
.toolbar{margin-top:44px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;display:grid;gap:12px}
.searchrow{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.search{flex:1 1 260px;min-width:0;background:var(--canvas);border:1px solid var(--borderStrong);border-radius:8px;padding:10px 12px;color:var(--text);font:400 13px/1.4 var(--sans)}
.search::placeholder{color:var(--faint)}
.count{margin:0;font-size:12.5px;color:var(--muted);white-space:nowrap}
.count b{color:var(--text);font-weight:600}
.filterrow{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center}
.fgroup{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-width:0}
.flabel{font:500 10px/1.4 var(--sans);letter-spacing:.11em;text-transform:uppercase;color:var(--faint)}
.chip{background:var(--canvas);border:1px solid var(--border);color:var(--muted);border-radius:999px;padding:6px 11px;font:500 12px/1 var(--sans);cursor:pointer}
.chip:hover{color:var(--text);border-color:var(--borderStrong)}
.chip[aria-pressed="true"]{background:var(--text);border-color:var(--text);color:var(--canvas)}
.selectwrap{display:flex;align-items:center;gap:6px;min-width:0}
select.filter{max-width:min(100%,260px);background:var(--canvas);border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 9px;font:500 12px/1.3 var(--sans)}
.legend{margin:2px 0 0;padding:12px 0 0;border-top:1px solid var(--border);display:grid;gap:8px}
.legend > div{display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 12px;align-items:baseline}
.legend dt{margin:0}
.legend dd{margin:0;color:var(--muted);font-size:12.5px}

/* Findings --------------------------------------------------------- */
.findings{display:flex;flex-direction:column;gap:12px}
.finding{background:var(--surface);border:1px solid var(--border);border-left-width:3px;border-left-style:solid;border-radius:12px;min-width:0}
.finding[data-sev="critical"]{border-left-color:var(--sev-critical)}
.finding[data-sev="high"]{border-left-color:var(--sev-high)}
.finding[data-sev="medium"]{border-left-color:var(--sev-medium)}
.finding[data-sev="low"]{border-left-color:var(--sev-low)}
.finding[data-sev="info"]{border-left-color:var(--sev-info)}
.finding[data-ver="strong_evidence"]{border-left-style:dashed}
.finding[data-ver="needs_review"]{border-left-style:dotted;background:var(--canvas)}
.finding[data-rank="lead"]{background:var(--raised);border-color:var(--borderStrong)}
.finding[data-state="fixed"]{border-left-color:var(--ok);border-left-style:solid}
.finding[hidden]{display:none}
.fhead{list-style:none;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px 16px;padding:16px 18px;cursor:pointer}
.fhead:hover{background:var(--hover);border-radius:12px}
.fhead::-webkit-details-marker{display:none}
.disclosure[open] > .fhead{border-bottom:1px solid var(--border);border-radius:12px 12px 0 0}
.marks{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:6px}
.sev,.ver,.status,.cat,.base{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:6px;padding:3px 7px;font:600 10px/1.35 var(--mono);letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
.sev{color:var(--text);border-color:var(--borderStrong)}
.sev[data-sev="critical"]{background:var(--text);color:var(--canvas);border-color:var(--text)}
.sev[data-sev="high"]{border-color:var(--text)}
.sev[data-sev="medium"]{color:var(--muted)}
.sev[data-sev="low"],.sev[data-sev="info"]{color:var(--faint);border-color:var(--border)}
.ver{color:var(--muted);font-weight:500;letter-spacing:.04em;text-transform:none}
.ver[data-ver="verified"]{color:var(--okInk);border-color:var(--okLine);border-style:solid;background:var(--okSoft)}
.ver[data-ver="strong_evidence"]{color:var(--text);border-color:var(--borderStrong);border-style:dashed}
.ver[data-ver="needs_review"]{color:var(--muted);border-style:dotted;border-color:var(--borderStrong)}
.status{color:var(--okInk);border-color:var(--okLine);font-weight:500;letter-spacing:.04em;text-transform:none}
.cat,.base{color:var(--faint);font-weight:500;letter-spacing:.04em;text-transform:none}
.base[data-baseline="new"]{color:var(--text);border-color:var(--borderStrong)}
.ftitle{min-width:0}
.ftitle h3{font:600 16px/1.4 var(--sans);margin:0 0 5px;letter-spacing:-.01em}
.ftitle h3 .fid{color:var(--faint);font-family:var(--mono);font-size:13px;font-weight:500;margin-right:8px}
.finding[data-rank="lead"] .ftitle h3{font-size:18px;line-height:1.35}
.where{font:400 12px/1.55 var(--mono);color:var(--muted);overflow-wrap:anywhere}
.lede-impact{margin:9px 0 0;color:var(--muted);font-size:13px}
.finding[data-rank="lead"] .lede-impact{color:var(--text);font-size:14px;line-height:1.6;max-width:74ch}
.chev{align-self:center;justify-self:end;font:500 11px/1 var(--sans);color:var(--faint);white-space:nowrap}
.chev .less{display:none}
.disclosure[open] .chev .more{display:none}
.disclosure[open] .chev .less{display:inline}
.fbody{padding:2px 18px 20px}
.fbody h4{font:600 11px/1.3 var(--sans);letter-spacing:.11em;text-transform:uppercase;color:var(--faint);margin:24px 0 8px}
.fbody p{margin:0 0 10px;max-width:78ch}
.fbody p:last-child{margin-bottom:0}
.vmean{display:block;margin:16px 0 0;padding:12px 14px;background:var(--raised);border:1px solid var(--border);border-left-width:3px;border-left-style:solid;border-radius:8px}
.finding[data-ver="needs_review"] .vmean{background:var(--surface)}
.vmean[data-ver="verified"]{border-left-color:var(--ok)}
.vmean[data-ver="strong_evidence"]{border-left-color:var(--text);border-left-style:dashed}
.vmean[data-ver="needs_review"]{border-left-color:var(--faint);border-left-style:dotted}
.vmean b{display:block;font:600 12px/1.4 var(--sans);letter-spacing:.02em}
.vmean p{margin:5px 0 0;color:var(--muted);font-size:13px;max-width:78ch}
.evidence{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}
.evidence li{border:1px solid var(--border);background:var(--raised);border-radius:var(--radius);padding:12px 14px;min-width:0}
.ekind{font:600 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.evidence p{margin:8px 0 0;color:var(--text);max-width:78ch}
.eloc{font:400 11px/1.5 var(--mono);color:var(--faint);margin-top:6px;overflow-wrap:anywhere}
.redacted{color:var(--faint);font-size:11px;margin-top:8px;font-style:italic}
.path{list-style:none;margin:4px 0 0;padding:0}
.path li{position:relative;padding:0 0 16px 26px;min-width:0}
.path li::before{content:"";position:absolute;left:6px;top:7px;bottom:0;width:1px;background:var(--border)}
.path li:last-child{padding-bottom:0}
.path li:last-child::before{display:none}
.path li::after{content:"";position:absolute;left:2px;top:4px;width:9px;height:9px;border-radius:50%;border:1px solid var(--borderStrong);background:var(--surface)}
.path li:first-child::after{border-color:var(--text)}
.path li:last-child::after{background:var(--text);border-color:var(--text)}
.path .step{display:block;font:600 10px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.path .detail{display:block;margin-top:3px;color:var(--text);font-size:13px;overflow-wrap:anywhere;max-width:76ch}
.refs{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:0;list-style:none}
.refs li{font:500 11px/1.35 var(--mono);border:1px solid var(--border);border-radius:6px;padding:3px 7px;color:var(--muted)}
.refs li b{color:var(--text);font-weight:600}
pre.plain{margin:10px 0 0;padding:12px 14px;background:var(--canvas);border:1px solid var(--border);border-radius:8px;overflow-x:auto}
pre.plain code{font:400 12px/1.6 var(--mono)}
.blocknote{margin:8px 0 0;color:var(--faint);font-size:11.5px}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:24px;padding-top:18px;border-top:1px solid var(--border)}
.copy{background:var(--text);color:var(--canvas);border:1px solid var(--text);border-radius:8px;padding:10px 14px;font:700 12px/1 var(--sans);cursor:pointer}
.copy:hover{opacity:.88}
.copy.secondary{background:var(--surface);color:var(--text);border:1px solid var(--borderStrong);font-weight:600}
.copy.secondary:hover{background:var(--hover);opacity:1}
.copy.tiny{padding:7px 11px;font-size:11px}
.copy[data-done="true"]{background:var(--okSoft);color:var(--okInk);border-color:var(--okLine)}
.hint{color:var(--faint);font-size:11.5px;align-self:center;max-width:60ch}
.codewrap{margin-top:10px}
.codewrap .codeblock{margin-top:0}
.codebar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}

/* Empty states ----------------------------------------------------- */
.empty{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px}
.empty b{display:block;font:600 16px/1.4 var(--sans);margin-bottom:6px}
.empty p{margin:0;color:var(--muted);max-width:78ch}
.calm{color:var(--muted);margin:0;max-width:78ch}

/* Tables ------------------------------------------------------------ */
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;background:var(--surface)}
.tablewrap:focus-visible{outline:2px solid var(--focus);outline-offset:-2px}
table{border-collapse:collapse;width:100%;min-width:620px;font-size:13px}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:top}
thead th{font:600 10px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint);background:var(--raised);white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
td.mono{font-family:var(--mono);font-size:12px;overflow-wrap:anywhere}
td a{color:var(--text);text-decoration:underline;text-underline-offset:3px}
.fixlist{max-width:56ch}
.nw{white-space:nowrap}

footer{margin-top:60px;padding-top:20px;border-top:1px solid var(--border);color:var(--faint);font-size:11.5px;display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between}
footer span{overflow-wrap:anywhere}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(12px);background:var(--raised);border:1px solid var(--borderStrong);border-radius:999px;padding:10px 18px;font-size:12px;opacity:0;pointer-events:none;transition:opacity .16s ease, transform .16s ease;z-index:40}
.toast[data-visible="true"]{opacity:1;transform:translateX(-50%) translateY(0)}

/* Motion ------------------------------------------------------------ */
@keyframes rise{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
.finding.enter{animation:rise .22s cubic-bezier(.2,.7,.3,1) both}
@media (prefers-reduced-motion: reduce){
  .toast{transition:none}
  .finding.enter{animation:none}
  html{scroll-behavior:auto}
  *,*::before,*::after{animation-duration:.001ms !important;animation-iteration-count:1 !important;transition-duration:.001ms !important}
}
@media (prefers-reduced-motion: no-preference){html{scroll-behavior:smooth}}

/* Narrow ------------------------------------------------------------ */
@media (max-width:760px){
  .page{padding:24px 16px 72px}
  h1{font-size:24px}
  .section{margin-top:38px}
  .verdict{padding:20px 16px 18px}
  .verdict > h2{font-size:20px}
  .fixfirst li{grid-template-columns:minmax(0,1fr);padding:14px 14px 14px 46px}
  .fixfirst li::before{left:12px}
  .fhead{padding:14px;grid-template-columns:minmax(0,1fr)}
  .chev{display:none}
  .fbody{padding:2px 14px 18px}
  .finding[data-rank="lead"] .ftitle h3{font-size:17px}
  .toolbar{padding:12px}
  .count{white-space:normal}

  /*
   * Touch sizing.
   *
   * A filter chip is 26px tall at desktop density and a fingertip needs about
   * 44, so on a phone every control in the toolbar grows to that height rather
   * than being aimed at. The chips keep their pill shape — only the vertical
   * padding changes — and the row is allowed to wrap, because six chips at 44px
   * do not fit on one line at 375px and a horizontally scrolling filter bar is
   * worse than two rows of one.
   */
  .chip,.search,.filter,.copy{min-height:44px}
  .chip{padding:0 14px;display:inline-flex;align-items:center}
  .search{padding:11px 12px}
  .copy{padding:0 16px;display:inline-flex;align-items:center;justify-content:center}
  .copy.tiny{padding:0 14px;font-size:12px}
  /*
   * A finding id in a table, or a fix-first title, is a link a thumb has to hit.
   * The tables scroll inside their own container, so growing the link costs the
   * layout nothing.
   */
  .tablewrap a{min-height:44px;display:inline-flex;align-items:center}
  .ff-title{display:block;min-height:44px;padding:10px 0 6px}
  .refs li{display:inline-flex;align-items:center}
  .refs a{min-height:44px;min-width:44px;display:inline-flex;align-items:center;justify-content:center}
  .filter{padding:0 30px 0 10px}
  .filterrow,.chipset{gap:8px;row-gap:8px}
  summary,.fhead{min-height:44px}
}

/* Print -------------------------------------------------------------- */
@media print{
  :root{color-scheme:light;--canvas:#fff;--surface:#fff;--raised:#fff;--text:#101010;--muted:#3d3d3d;--faint:#5b5b5b;--border:#cfcfcf;--borderStrong:#9a9a9a;--okInk:#17752A;--ok:#17752A}
  body{background:#fff;color:#101010}
  .page{max-width:none;padding:0}
  .toolbar,.toc,.actions,.toast,.skip,.chev,.codebar,.copy{display:none !important}
  .shell{display:block}
  .section{margin-top:26px}
  .verdict,.finding,.num,.card,.evidence li,.empty,.tablewrap,pre.plain,.vmean,.fixfirst li{border-color:#cfcfcf;background:#fff;break-inside:avoid;box-shadow:none}
  .finding{border-left-width:3px}
  .disclosure .fbody{display:block !important}
  .sev[data-sev="critical"]{background:#101010;color:#fff}
  .bar{border-color:#cfcfcf}
  thead th{background:#f2f2f2;color:#3d3d3d}
  a[href]::after{content:" (" attr(href) ")";font-size:10px;color:#5b5b5b}
  a[href^="#"]::after{content:""}
  @page{margin:16mm}
}
`;
