const PREVIEW_AGENT = "ExampleAppLinkPreview/1.2 (+https://example.com/bots)";
const FETCH_TIMEOUT_MS = 4000;
const MAX_HTML_CHARS = 200_000;

const previewSchema = {
  body: {
    type: "object",
    required: ["url"],
    additionalProperties: false,
    properties: { url: { type: "string", format: "uri", maxLength: 2048 } },
  },
};

function readMetaTag(html, property) {
  const pattern = new RegExp(
    `<meta[^>]+(?:property|name)=["']${property}["'][^>]+content=["']([^"']*)["']`,
    "i"
  );
  return html.match(pattern)?.[1] ?? null;
}

function buildPreview(html) {
  return {
    title: readMetaTag(html, "og:title") ?? html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] ?? null,
    description: readMetaTag(html, "og:description") ?? readMetaTag(html, "description"),
    image: readMetaTag(html, "og:image"),
    siteName: readMetaTag(html, "og:site_name"),
  };
}

export default async function (fastify, options) {
  const previews = fastify.mongo.db.collection("link_previews");

  // POST /link-previews
  // The composer calls this while the author types so a pasted link renders as a card.
  fastify.post(
    "/link-previews",
    { preHandler: [fastify.authenticate], schema: previewSchema },
    async (request, reply) => {
      const target = request.body.url;
      const cached = await previews.findOne({ url: target });

      if (cached) {
        return reply.send({ preview: cached.preview, cached: true });
      }

      const response = await fetch(target, {
        redirect: "follow",
        headers: { "user-agent": PREVIEW_AGENT, accept: "text/html,application/xhtml+xml" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (!response.ok) {
        return reply.code(422).send({ error: "preview_unavailable", status: response.status });
      }

      const html = (await response.text()).slice(0, MAX_HTML_CHARS);
      const preview = buildPreview(html);

      await previews.insertOne({
        url: target,
        preview,
        requestedBy: request.user.accountId,
        fetchedAt: new Date(),
      });

      return reply.send({ preview, cached: false });
    }
  );
}
