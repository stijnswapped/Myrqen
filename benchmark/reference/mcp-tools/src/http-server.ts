import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express, { type Request, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import { lookupSession } from './auth/sessions.js';
import { httpPort } from './config/environment.js';
import { createSupportServer, serverInfo } from './index.js';

const app = express();
app.use(express.json({ limit: '4mb' }));

/** Live MCP sessions, keyed by the transport's own session id. */
const transports = new Map<string, StreamableHTTPServerTransport>();

function rpcError(code: number, message: string) {
  return { jsonrpc: '2.0' as const, error: { code, message }, id: null };
}

function bearerToken(req: Request): string | null {
  const header = req.header('authorization');
  if (!header || !header.startsWith('Bearer ')) {
    return null;
  }
  const token = header.slice('Bearer '.length).trim();
  return token === '' ? null : token;
}

app.post('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.header('mcp-session-id');
  if (sessionId) {
    const live = transports.get(sessionId);
    if (!live) {
      res.status(404).json(rpcError(-32001, 'Unknown MCP session'));
      return;
    }
    await live.handleRequest(req, res, req.body);
    return;
  }

  if (!isInitializeRequest(req.body)) {
    res.status(400).json(rpcError(-32000, 'Expected an initialize request'));
    return;
  }

  const token = bearerToken(req);
  const session = token ? await lookupSession(token) : null;

  // The stdio entry point builds the server with a null session and every tool
  // copes with that already, so an unrecognised or expired token can fall
  // through the same way instead of killing the whole connection - the client
  // will get a permission error from the first tool it tries.
  const server = createSupportServer({ session });

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => {
      transports.set(id, transport);
    },
  });
  transport.onclose = () => {
    if (transport.sessionId) {
      transports.delete(transport.sessionId);
    }
  };

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// The notification stream and the teardown call both need an established
// session, so they only ever look the transport up.
app.get('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.header('mcp-session-id');
  const live = sessionId ? transports.get(sessionId) : undefined;
  if (!live) {
    res.status(404).json(rpcError(-32001, 'Unknown MCP session'));
    return;
  }
  await live.handleRequest(req, res);
});

app.delete('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.header('mcp-session-id');
  const live = sessionId ? transports.get(sessionId) : undefined;
  if (!live) {
    res.status(404).json(rpcError(-32001, 'Unknown MCP session'));
    return;
  }
  await live.handleRequest(req, res);
});

app.get('/healthz', (_req: Request, res: Response) => {
  res.json({ ok: true, service: serverInfo.name, version: serverInfo.version });
});

app.listen(httpPort, () => {
  process.stderr.write(`${serverInfo.name} listening on :${httpPort}/mcp\n`);
});
