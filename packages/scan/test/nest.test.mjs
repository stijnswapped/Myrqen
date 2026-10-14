import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/**
 * The NestJS adapter, exercised on source text rather than on a fixture.
 *
 * What is being proved here is mostly the second half of an entry point. A route
 * label that says `GET /billing/invoices/:id` is nice for the report; the seeds
 * are what decide whether thirty-six data-flow rules can see anything at all in
 * a controller, because Nest hands the caller's data over as parameters that
 * look exactly like every other parameter. So each case asserts the bindings as
 * well as the address, and the trusted cases assert the absence of a seed —
 * `@Session()` named as caller data would invent findings across the whole file.
 */

const adapterPath = fileURLToPath(new URL("../dist/ast/frameworks/nest.js", import.meta.url));
const adapterModule = existsSync(adapterPath) ? await import(new URL("../dist/ast/frameworks/nest.js", import.meta.url).href) : null;

if (!adapterModule) {
  test.skip("nest adapter tests need `pnpm --filter @myrqen/scan build` first", () => {});
} else {
  const { nestAdapter } = adapterModule;

  /** A ParsedFile built in memory, so a case is readable beside its assertions. */
  function parsed(text, relativePath = "src/invoices.controller.ts") {
    const isJavaScript = /\.[cm]?jsx?$/.test(relativePath);
    const source = ts.createSourceFile(
      relativePath,
      text,
      ts.ScriptTarget.Latest,
      true,
      isJavaScript ? ts.ScriptKind.JS : ts.ScriptKind.TS
    );
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text,
      source,
      language: isJavaScript ? "JavaScript" : "TypeScript"
    };
  }

  const detect = (text, relativePath) => {
    const file = parsed(text, relativePath);
    return nestAdapter.applies(file) ? nestAdapter.detect(file) : [];
  };

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name).sort();
  const originOf = (entry, name) => (entry.seeds ?? []).find((seed) => seed.name === name)?.origin;

  test("the controller path and the method path make one address", () => {
    const entries = detect(`
      import { Controller, Get, Post } from '@nestjs/common';

      @Controller('billing/invoices')
      export class InvoicesController {
        @Get(':id')
        findOne(@Param('id') id) { return id; }

        @Post()
        create(@Body() dto) {}
      }
    `);
    assert.deepEqual(addresses(entries), ["GET /billing/invoices/:id", "POST /billing/invoices"]);
    assert.equal(entries[0].framework, "nest");
    assert.equal(entries[0].kind, "http");
  });

  test("Nest's own parameter syntax is kept as written", () => {
    const entries = detect(`
      import { Controller, Get } from '@nestjs/common';
      @Controller('orders')
      export class OrdersController {
        @Get(':orderId/items/:itemId')
        item(@Param('itemId') itemId) {}
      }
    `);
    assert.deepEqual(addresses(entries), ["GET /orders/:orderId/items/:itemId"]);
  });

  test("a controller decorator with no argument leaves the method path alone", () => {
    const entries = detect(`
      import { Controller, Delete } from '@nestjs/common';
      @Controller()
      export class RootController {
        @Delete('cache') purge() {}
      }
    `);
    assert.deepEqual(addresses(entries), ["DELETE /cache"]);
  });

  test("the object form of the controller decorator contributes its path and not its version", () => {
    const entries = detect(`
      import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'admin/users', version: '1' })
      export class UsersController {
        @Get() list() {}
      }
    `);
    // Whether the version becomes a /v1 prefix, a header, or a media type is an
    // application-wide setting that lives in another file entirely.
    assert.deepEqual(addresses(entries), ["GET /admin/users"]);
  });

  test("every parameter decorator that carries caller data becomes a seed", () => {
    const [entry] = detect(`
      import { Controller, Post, Param, Query, Body, Headers, Req } from '@nestjs/common';
      @Controller('search')
      export class SearchController {
        @Post(':scope')
        run(@Param('scope') scope, @Query() query, @Body('term') term, @Headers('x-tenant') tenant, @Req() req) {}
      }
    `);
    assert.deepEqual(seedNames(entry), ["query", "req", "scope", "tenant", "term"]);
    assert.equal(originOf(entry, "scope"), "@Param('scope') (caller-controlled route parameter)");
    assert.equal(originOf(entry, "query"), "@Query() (caller-controlled query string)");
    assert.equal(originOf(entry, "term"), "@Body('term') (caller-controlled request body)");
    assert.equal(originOf(entry, "tenant"), "@Headers('x-tenant') (caller-controlled request header)");
    assert.equal(originOf(entry, "req"), "@Req() (inbound request)");
  });

  test("a destructured body seeds every name it binds", () => {
    const [entry] = detect(`
      import { Controller, Post, Body } from '@nestjs/common';
      @Controller('checkout')
      export class CheckoutController {
        @Post()
        create(@Body() { name, price: unitPrice, ...rest }) {}
      }
    `);
    // The parameter itself has no name, so seeding it would seed nothing and all
    // three fields would flow through the handler untracked.
    assert.deepEqual(seedNames(entry), ["name", "rest", "unitPrice"]);
    assert.equal(originOf(entry, "unitPrice"), "@Body() (caller-controlled request body)");
  });

  test("a session and a response object are trusted rather than seeded", () => {
    const [entry] = detect(`
      import { Controller, Get, Param, Session, Res } from '@nestjs/common';
      @Controller('me')
      export class MeController {
        @Get(':id')
        show(@Param('id') id, @Session() session, @Res() res) {}
      }
    `);
    assert.deepEqual(seedNames(entry), ["id"], "only the route parameter came from the caller");
    assert.deepEqual([...entry.trustedParameters].sort(), ["res", "session"]);
  });

  test("an upload, an address and a host segment are caller-influenced enough to seed", () => {
    const [entry] = detect(`
      import { Controller, Post, UploadedFile, Ip, HostParam } from '@nestjs/common';
      @Controller('avatars')
      export class AvatarsController {
        @Post()
        upload(@UploadedFile() file, @Ip() ip, @HostParam('sub') sub) {}
      }
    `);
    assert.deepEqual(seedNames(entry), ["file", "ip", "sub"]);
    assert.equal(originOf(entry, "file"), "@UploadedFile() (caller-controlled file upload)");
  });

  test("a decorator the adapter does not know says nothing about its parameter", () => {
    const [entry] = detect(`
      import { Controller, Get, Param } from '@nestjs/common';
      @Controller('reports')
      export class ReportsController {
        @Get(':id')
        show(@Param('id') id, @CurrentUser() user, @Tenant() tenant) {}
      }
    `);
    // A project's own decorator could be reading a verified JWT or reading a
    // header. Guessing either way is worse than leaving the binding to the
    // generic model.
    assert.deepEqual(seedNames(entry), ["id"]);
    assert.equal(entry.trustedParameters, undefined);
  });

  test("stacked verb decorators are two addresses on one body", () => {
    const entries = detect(`
      import { Controller, Get, Post } from '@nestjs/common';
      @Controller('feed')
      export class FeedController {
        @Get()
        @Post('refresh')
        feed(@Body() dto) {}
      }
    `);
    assert.deepEqual(addresses(entries), ["GET /feed", "POST /feed/refresh"]);
    assert.deepEqual(seedNames(entries[1]), ["dto"], "both addresses reach the same tainted binding");
  });

  test("a catch-all verb is reported as ANY", () => {
    const entries = detect(`
      import { Controller, All } from '@nestjs/common';
      @Controller('webhooks')
      export class WebhookController {
        @All('stripe') receive(@Body() payload) {}
      }
    `);
    assert.deepEqual(addresses(entries), ["ANY /webhooks/stripe"]);
  });

  test("the entry point points at the method body and at the decorator's line", () => {
    const text = [
      "import { Controller, Get } from '@nestjs/common';",
      "@Controller('a')",
      "export class AController {",
      "  @Get(':id')",
      "  read(@Param('id') id) {}",
      "}"
    ].join("\n");
    const [entry] = detect(text);
    assert.equal(entry.line, 4, "the decorator is the line a reader searches for");
    assert.ok(ts.isMethodDeclaration(entry.node), "the handler is the method itself");
  });

  test("a verb decorator with no framework anywhere in the file is not a route", () => {
    const text = `
      import { Get } from './lib/cache-decorators';
      export class Prices {
        @Get('eur') read() {}
      }
    `;
    // `@Get` is a common word. Claiming this one would publish an endpoint that
    // does not exist and attribute every finding in the class to it.
    assert.deepEqual(detect(text), []);
    assert.equal(nestAdapter.applies(parsed(text)), false);
  });

  test("an undecorated class in a framework file still exposes its routes", () => {
    const entries = detect(`
      import { Get, HttpResponseOK } from '@foal/core';
      export class ApiController {
        @Get('/products/:id')
        readProduct(ctx) { return new HttpResponseOK(); }
      }
    `);
    // Foal mounts a plain class; the import is what makes @Get mean HTTP here.
    assert.deepEqual(addresses(entries), ["GET /products/:id"]);
  });

  test("a JavaScript controller loaded with require is recognised too", () => {
    const entries = detect(
      `
      const { Controller, Get, Param } = require('@nestjs/common');
      @Controller('legacy')
      class LegacyController {
        @Get(':slug')
        read(@Param('slug') slug) {}
      }
    `,
      "src/legacy.controller.js"
    );
    assert.deepEqual(addresses(entries), ["GET /legacy/:slug"]);
    assert.deepEqual(seedNames(entries[0]), ["slug"]);
  });

  test("a service is not an entry point", () => {
    const entries = detect(`
      import { Injectable } from '@nestjs/common';
      @Injectable()
      export class InvoiceService {
        findOne(id) { return id; }
      }
    `);
    assert.deepEqual(entries, [], "nothing in a service is reachable by a caller directly");
  });
}
