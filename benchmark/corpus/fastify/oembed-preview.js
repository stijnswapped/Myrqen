const PREVIEW_AGENT = "ExampleAppLinkPreview/1.2 (+https://example.com/bots)";
const FETCH_TIMEOUT_MS = 4000;
const MAX_JSON_CHARS = 100_000;

const PROVIDERS = {
  "www.youtube.com": "https://www.youtube.com/oembed",
  "vimeo.com": "https://vimeo.com/api/oembed.json",
  "soundcloud.com": "https://soundcloud.com/oembed",
  "www.figma.com": "https://www.figma.com/api/oembed",
};

const previewSchema = {
  body: {
    type: "object",
    required: ["url"],
    additionalProperties: false,
    properties: { url: { type: "string", format: "uri", maxLength: 2048 } },
  },
};

function resolveProvider(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  if (parsed.protocol !== "https:") {
    return null;
  }

  const endpoint = PROVIDERS[parsed.hostname];
  if (!endpoint) {
    return null;
  }

  const request = new URL(endpoint);
  request.searchParams.set("url", parsed.toString());
  request.searchParams.set("format", "json");
  return request;
}

export default async function (fastify, options) {
  const previews = fastify.mongo.db.collection("embed_previews");

  // POST /embed-previews
  // The composer calls this while the author types so a pasted media link renders
  // as a player card, using each provider's published oEmbed endpoint.
  fastify.post(
    "/embed-previews",
    { preHandler: [fastify.authenticate], schema: previewSchema },
    async (request, reply) => {
      const endpoint = resolveProvider(request.body.url);

      if (!endpoint) {
        return reply.code(422).send({ error: "provider_not_supported" });
      }

      const cached = await previews.findOne({ url: request.body.url });

      if (cached) {
        return reply.send({ preview: cached.preview, cached: true });
      }

      const response = await fetch(endpoint, {
        redirect: "error",
        headers: { "user-agent": PREVIEW_AGENT, accept: "application/json" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (!response.ok) {
        return reply.code(422).send({ error: "preview_unavailable", status: response.status });
      }

      const payload = JSON.parse((await response.text()).slice(0, MAX_JSON_CHARS));
      const preview = {
        title: payload.title ?? null,
        provider: payload.provider_name ?? null,
        thumbnail: payload.thumbnail_url ?? null,
        width: payload.width ?? null,
        height: payload.height ?? null,
      };

      await previews.insertOne({
        url: request.body.url,
        preview,
        requestedBy: request.user.accountId,
        fetchedAt: new Date(),
      });

      return reply.send({ preview, cached: false });
    }
  );
}
