/**
 * Console Companion background worker.
 *
 * The popup talks to it over runtime messaging; the web console talks to it over
 * external messaging so the "Open in Companion" button can hand a project across
 * without a round trip through our API.
 */

const API_BASE = "https://api.console.example.com";
const CACHE_TTL_MS = 30_000;

const cache = new Map();

async function readToken() {
  const { apiToken } = await chrome.storage.local.get("apiToken");
  if (!apiToken) throw new Error("not_linked");
  return apiToken;
}

async function callApi(path) {
  const cached = cache.get(path);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.body;

  const response = await fetch(`${API_BASE}${path}`, {
    headers: { authorization: `Bearer ${await readToken()}`, accept: "application/json" },
  });
  if (!response.ok) throw new Error(`api_${response.status}`);

  const body = await response.json();
  cache.set(path, { at: Date.now(), body });
  return body;
}

const commands = {
  listProjects: () => callApi("/v1/projects"),
  projectBuilds: ({ projectId }) => callApi(`/v1/projects/${encodeURIComponent(projectId)}/builds`),
  buildLog: ({ buildId }) => callApi(`/v1/builds/${encodeURIComponent(buildId)}/log`),
};

function dispatch(message) {
  const command = commands[message?.type];
  if (!command) return Promise.reject(new Error("unknown_command"));
  return command(message);
}

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  dispatch(message).then(
    (result) => sendResponse({ ok: true, result }),
    (error) => {
      console.warn("companion command failed", message?.type, error.message);
      sendResponse({ ok: false, error: error.message });
    },
  );
  return true;
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  dispatch(message).then(
    (result) => sendResponse({ ok: true, result }),
    (error) => sendResponse({ ok: false, error: error.message }),
  );
  return true;
});

chrome.alarms.create("refresh", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener(() => cache.clear());
