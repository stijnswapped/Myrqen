/**
 * Highlight panel.
 *
 * Runs on every page. When the workspace already has highlights saved for the
 * current origin the panel slides in from the right so the reader can see what
 * a teammate marked before they start reading. Highlights are stored per
 * workspace, so what lands here was captured by whoever on the team happened to
 * be reading whatever page at the time.
 *
 * Styles live in a shadow root — the host page's CSS is not ours to fight.
 */
import { sendCommand } from "../shared/messaging";

const PANEL_ID = "marginalia-highlight-panel";
const PANEL_STYLES = `
  :host { all: initial; }
  .mg-panel { position: fixed; top: 84px; right: 0; width: 300px; z-index: 2147483000;
              font: 13px/1.5 system-ui, sans-serif; background: #fff; border: 1px solid #e2e2e2; }
  .mg-panel__title { padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #eee; }
  .mg-list { list-style: none; margin: 0; padding: 0; max-height: 60vh; overflow: auto; }
  .mg-note { padding: 10px 12px; border-bottom: 1px solid #f2f2f2; }
  .mg-note__quote { margin: 0 0 6px; color: #1b1b1b; }
  .mg-note__meta { color: #767676; font-size: 12px; }
`;

let root = null;

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
  return `
    <li class="mg-note" data-note-id="${note.id}">
      <blockquote class="mg-note__quote">${note.quote}</blockquote>
      <div class="mg-note__meta">${note.author} · ${note.sourceTitle}</div>
    </li>`;
}

function render(shadow, notes) {
  const list = shadow.querySelector(".mg-list");
  if (!list) return;
  list.innerHTML = notes.map(noteMarkup).join("");
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
