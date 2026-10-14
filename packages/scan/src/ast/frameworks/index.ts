import { registerAdapter } from "../entrypoints.js";
import { nestAdapter } from "./nest.js";
import { sveltekitAdapter, remixAdapter } from "./sveltekit.js";
import { nitroAdapter } from "./nitro.js";
import { serverlessAdapter } from "./serverless.js";
import { workersAdapter } from "./workers.js";
import { desktopCliAdapter } from "./desktop-cli.js";
import { denoAdapter } from "./deno.js";
import { bunAdapter } from "./bun.js";
import { astroAdapter } from "./astro.js";
import { realtimeAdapter } from "./realtime.js";
import { extensionAdapter } from "./extension.js";
import { tanstackSolidAdapter } from "./tanstack-solid.js";
import { adonisAdapter } from "./adonis.js";
import { convexAdapter } from "./convex.js";
import { hapiAdapter } from "./hapi.js";
import { effectAdapter } from "./effect.js";
import { declaredEndpointAdapter } from "./declared-endpoint.js";

/**
 * The registry.
 *
 * Every architecture the engine understands is listed here once. Adding another
 * one is a new file plus a line in this list — nothing in the rules, the taint
 * model, or the report has to know the framework exists, which is the whole
 * point of separating "where does data enter" from "what is wrong with it".
 */
export function registerFrameworkAdapters(): void {
  registerAdapter(nestAdapter);
  registerAdapter(sveltekitAdapter);
  registerAdapter(remixAdapter);
  registerAdapter(nitroAdapter);
  registerAdapter(serverlessAdapter);
  registerAdapter(workersAdapter);
  registerAdapter(desktopCliAdapter);
  registerAdapter(denoAdapter);
  registerAdapter(bunAdapter);
  registerAdapter(astroAdapter);
  registerAdapter(realtimeAdapter);
  registerAdapter(extensionAdapter);
  registerAdapter(tanstackSolidAdapter);
  registerAdapter(adonisAdapter);
  registerAdapter(convexAdapter);
  registerAdapter(hapiAdapter);
  registerAdapter(effectAdapter);
  /*
   * Last, deliberately. Every adapter above knows one framework and can say more about
   * it than this one can: which container is the server's, which wrapper is internal,
   * how that framework spells a path parameter. This recognises the shape they all share
   * — a function handed to something, next to a path — and exists for the framework
   * nobody has written an adapter for, which on any given day is most of them.
   */
  registerAdapter(declaredEndpointAdapter);
}

registerFrameworkAdapters();
