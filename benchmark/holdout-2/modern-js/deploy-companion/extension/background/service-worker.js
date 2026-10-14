/**
 * Deploy Companion background worker.
 *
 * The popup talks to it over runtime messaging; the web console talks to it over
 * external messaging so the "Open in Companion" button can hand an environment
 * across without a round trip through our API.
 */

const API_BASE = "https://api.deploy.example.com";
const CACHE_TTL_MS = 30_000;

/**
 * The manifest already narrows `externally_connectable`, but the listener checks
 * the sender itself as well: a match pattern is a routing rule and this is the
 * trust decision, so it does not get to depend on the manifest being right.
 */
const CONSOLE_ORIGIN = "https://app.deploy.example.com";

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
  listEnvironments: () => callApi("/v1/environments"),
  environmentReleases: ({ environmentId }) =>
    callApi(`/v1/environments/${encodeURIComponent(environmentId)}/releases`),
  releaseLog: ({ releaseId }) => callApi(`/v1/releases/${encodeURIComponent(releaseId)}/log`),
};

function dispatch(message) {
  const command = commands[message?.type];
  if (!command) return Promise.reject(new Error("unknown_command"));
  return command(message);
}

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (sender.origin !== CONSOLE_ORIGIN) {
    console.warn("external message refused", sender.origin);
    sendResponse({ ok: false, error: "forbidden_origin" });
    return false;
  }

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
