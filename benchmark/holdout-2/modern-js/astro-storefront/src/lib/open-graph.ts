/** Minimal Open Graph reader — enough for a link card, no DOM required. */
const META = /<meta\s[^>]*>/gi;
const ATTR = /(property|name|content)\s*=\s*"([^"]*)"/gi;

export interface Preview {
  title: string | null;
  description: string | null;
  image: string | null;
}

export function parseOpenGraph(html: string): Preview {
  const found: Record<string, string> = {};
  for (const tag of html.slice(0, 200_000).match(META) ?? []) {
    const attributes: Record<string, string> = {};
    for (const [, key, value] of tag.matchAll(ATTR)) attributes[key.toLowerCase()] = value;
    const key = attributes.property ?? attributes.name;
    if (key && attributes.content) found[key.toLowerCase()] = attributes.content;
  }
  return {
    title: found["og:title"] ?? null,
    description: found["og:description"] ?? null,
    image: found["og:image"] ?? null,
  };
}
