import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Parameter decorators that bind caller data, read wherever they appear.
 *
 * The NestJS adapter seeds a controller method that carries a verb decorator. The same
 * parameter decorators also hand caller data to GraphQL resolvers, WebSocket gateways and
 * the controllers of frameworks with their own route vocabulary (tsoa, inversify, Ts.ED,
 * type-graphql). A decorator counts only when it is imported from the framework that
 * defines it: a project's own `@Path()` or `@CurrentUser()` says nothing about its value.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-decorators-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const PKG = JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "@nestjs/common": "^10.0.0" } });
const commands = (result) => result.candidates.filter((candidate) => candidate.category === "command_injection");

test("a NestJS GraphQL resolver argument is caller data", async () => {
  const resolver = (parameter) => `import { Resolver, Mutation, Args } from "@nestjs/graphql";
import { exec } from "node:child_process";
@Resolver()
export class ThumbnailResolver {
  @Mutation(() => Boolean)
  render(${parameter}) {
    exec(\`convert /in/\${name}.png /out/\${name}.jpg\`);
    return true;
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver('@Args("name") name: string') })).length, 1);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver("name: string") })).length, 0);
});

test("a NestJS WebSocket message body is caller data; the socket is not", async () => {
  const gateway = (parameters, use) => `import { WebSocketGateway, SubscribeMessage, MessageBody, ConnectedSocket } from "@nestjs/websockets";
import { exec } from "node:child_process";
@WebSocketGateway()
export class ConvertGateway {
  @SubscribeMessage("convert")
  handle(${parameters}) {
    exec(\`convert /in/\${${use}}.png\`);
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/convert.gateway.ts": gateway("@MessageBody() name: string", "name") })).length, 1);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/convert.gateway.ts": gateway("@ConnectedSocket() client: any", "client.id") })).length, 0);
});

test("tsoa: @Path is caller data when imported from tsoa, and not when it is the project's own", async () => {
  const controller = (from) => `import { Route, Get, Path, Controller } from "${from}";
import { exec } from "node:child_process";
@Route("thumbnails")
export class ThumbnailController extends Controller {
  @Get("{name}")
  public async render(@Path() name: string): Promise<void> {
    exec(\`convert /in/\${name}.png\`);
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.controller.ts": controller("tsoa") })).length, 1);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.controller.ts": controller("./decorators") })).length, 0);
});

test("inversify-express-utils: @requestBody is caller data", async () => {
  const controller = `import { controller, httpPost, requestBody } from "inversify-express-utils";
import { exec } from "node:child_process";
@controller("/thumbnails")
export class ThumbnailController {
  @httpPost("/")
  public render(@requestBody() body: { name: string }) {
    exec(\`convert /in/\${body.name}.png\`);
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.controller.ts": controller })).length, 1);
});

test("type-graphql: @Arg is caller data", async () => {
  const resolver = `import { Resolver, Mutation, Arg } from "type-graphql";
import { exec } from "node:child_process";
@Resolver()
export class ThumbnailResolver {
  @Mutation(() => Boolean)
  render(@Arg("name") name: string): boolean {
    exec(\`convert /in/\${name}.png\`);
    return true;
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver })).length, 1);
});

test("a decorated resolver argument is followed into a service in another module", async () => {
  const resolver = (parameter) => `import { Resolver, Mutation, Args } from "@nestjs/graphql";
import { renderThumbnail } from "./thumbnail.service";
@Resolver()
export class ThumbnailResolver {
  @Mutation(() => Boolean)
  render(${parameter}) {
    renderThumbnail(name);
    return true;
  }
}
`;
  const service = `import { exec } from "node:child_process";
export function renderThumbnail(file: string) {
  exec(\`convert /in/\${file}.png\`);
}
`;
  const reported = await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver('@Args("name") name: string'), "src/thumbnail.service.ts": service });
  assert.equal(commands(reported).length, 1);
  const silent = await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver("name: string"), "src/thumbnail.service.ts": service });
  assert.equal(commands(silent).length, 0);
});

test("a project's own parameter decorator seeds nothing", async () => {
  const resolver = `import { Resolver, Mutation } from "@nestjs/graphql";
import { CurrentUser } from "./auth";
import { exec } from "node:child_process";
@Resolver()
export class ThumbnailResolver {
  @Mutation(() => Boolean)
  render(@CurrentUser() user: { id: string }) {
    exec(\`convert /in/\${user.id}.png\`);
    return true;
  }
}
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/thumbnail.resolver.ts": resolver })).length, 0);
});
