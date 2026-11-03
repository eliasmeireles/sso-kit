import { createServer } from 'node:http';
import { once } from 'node:events';

type Handler = (request: Request) => Promise<Response>;
const inMemory = process.env.SSO_KIT_TEST_TRANSPORT === 'memory';
const handlers = new Map<string, Handler>();
let nextPort = 30_000;

if (inMemory) {
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const handler = handlers.get(new URL(request.url).origin);
    if (!handler) throw new TypeError('Test provider is not listening');
    return handler(request);
  };
}

/** Uses real loopback HTTP by default; memory mode supports sandboxes that prohibit sockets. */
export async function createTransport(handler: Handler) {
  if (inMemory) {
    const origin = `http://127.0.0.1:${nextPort++}`;
    handlers.set(origin, handler);
    return { origin, async close() { handlers.delete(origin); } };
  }
  const server = createServer((request, response) => {
    void (async () => {
      let body = '';
      for await (const chunk of request) body += String(chunk);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        if (Array.isArray(value)) value.forEach((entry) => headers.append(name, entry));
        else if (value !== undefined) headers.set(name, value);
      }
      const result = await handler(new Request(`${origin}${request.url}`, {
        method: request.method ?? 'GET', headers, ...(body && { body }),
      }));
      response.writeHead(result.status, Object.fromEntries(result.headers));
      response.end(await result.text());
    })().catch(() => {
      response.writeHead(500);
      response.end();
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No TCP address');
  const origin = `http://127.0.0.1:${address.port}`;
  return {
    origin,
    async close() {
      const closed = once(server, 'close');
      server.close();
      server.closeAllConnections();
      await closed;
    },
  };
}
