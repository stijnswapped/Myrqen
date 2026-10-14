/**
 * Highlight panel.
 *
 * Runs on every page. When the workspace already has highlights saved for the
 * current origin the panel slides in from the right so the reader can see what
 * a teammate marked before they start reading. Highlights are stored per
 * workspace, so what lands here was captured by whoever on the team happened to
 * be reading whatever page at the time — treat every field as page text.
 *
 * Styles live in a shadow root — the host page's CSS is not ours to fight. The
 * shadow root is a styling boundary and nothing more: markup put inside it is
 * parsed by the same parser and runs in the same page.
 */
import { sendCommand } from "../shared/messaging";

const PANEL_ID = "marginalia-note-panel";
const PANEL_STYLES = `
  :host { all: initial; }
  .mg-panel { position: fixed; top: 84px; right: 0; width: 300px; z-index: 2147483000;
              font: 13px/1.5 system-ui, sans-serif; background: #fff; border: 1px solid #e2e2e2; }
  .mg-panel__title { padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #eee; }
  .mg-list { list-style: none; margin: 0; padding: 0; max-height: 60vh; overflow: auto; }
  .mg-note { padding: 10px 12px; border-bottom: 1px solid #f2f2f2; }
  .mg-note--flagged { border-left: 3px solid #c2410c; }
  .mg-note__quote { margin: 0 0 6px; color: #1b1b1b; }
  .mg-note__meta { color: #767676; font-size: 12px; }
`;

/** The only note classes that exist; anything else falls back to the plain one. */
const TONE_CLASS = { plain: "mg-note", flagged: "mg-note mg-note--flagged" };

let root = null;

/**
 * Round-trips a value through a text node so the parser gets `&amp;`, `&lt;`
 * and `&gt;` back instead of the characters that would have opened a tag. Only
 * correct for element content, which is the only place it is used below —
 * quotes survive it, so it is no good inside an attribute.
 */
function asText(value) {
  const holder = document.createElement("span");
  holder.textContent = value == null ? "" : String(value);
  return holder.innerHTML;
}

function mount() {
  if (document.getElementById(PANEL_ID)) return null;
  const host = document.createElement("div");
  host.id = PANEL_ID;
  const shadow = host.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = PANEL_STYLES;
  shadow.append(style);
  shadow.append(
    Object.assign(document.createElement("div"), {
      className: "mg-panel",
      innerHTML: '<div class="mg-panel__title">Team highlights</div><ul class="mg-list"></ul>'
    })
  );
  document.documentElement.append(host);
  return shadow;
}

function noteMarkup(note) {
  const tone = TONE_CLASS[note.tone] ?? TONE_CLASS.plain;
  return `
    <li class="${tone}">
      <blockquote class="mg-note__quote">${asText(note.quote)}</blockquote>
      <div class="mg-note__meta">${asText(note.author)} · ${asText(note.sourceTitle)}</div>
    </li>`;
}

function render(shadow, notes) {
  const list = shadow.querySelector(".mg-list");
  if (!list) return;
  list.innerHTML = notes.map(noteMarkup).join("");
  // The note id is the one value that would have to sit in an attribute, so it
  // goes in through the DOM after the parse instead of through the markup.
  list.querySelectorAll(".mg-note").forEach((item, index) => {
    item.dataset.noteId = notes[index].id;
  });
}

async function open() {
  const response = await sendCommand("clip.recent", { origin: location.origin, limit: 20 });
  if (!response?.ok || response.result.notes.length === 0) return;
  root = root ?? mount();
  if (root) render(root, response.result.notes);
}

// The worker pushes an update when a teammate saves a highlight while this tab
// is open, so the panel does not go stale behind the reader's back.
chrome.runtime.onMessage.addListener((message) => {
  if (message?.action === "panel.refresh") open();
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", open, { once: true });
} else {
  open();
}
