import { createServer } from "node:http";
import { createRouter } from "./lib/router.js";
import * as search from "./routes/search.js";
import * as directory from "./routes/directory.js";

const dispatch = createRouter([search, directory]);

createServer(async (incoming, outgoing) => {
  const request = new Request(`http://${incoming.headers.host}${incoming.url}`, { method: incoming.method });
  const response = await dispatch(request);
  outgoing.writeHead(response.status, Object.fromEntries(response.headers));
  outgoing.end(await response.text());
}).listen(Number(process.env.PORT ?? 8000));
