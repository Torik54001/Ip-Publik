import { createServer } from 'node:http';
import { main_handler } from './index.js';

const MAX_REQUEST_BYTES = 20 * 1024;

const server = createServer(async (req, res) => {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        res.writeHead(413, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ error: 'Request terlalu besar.' }));
        return;
      }
      chunks.push(chunk);
    }

    const requestUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const event = {
      httpMethod: req.method || 'GET',
      path: requestUrl.pathname,
      headers: req.headers || {},
      body: Buffer.concat(chunks).toString('utf8'),
      isBase64Encoded: false
    };

    const result = await main_handler(event);
    const statusCode = Number(result?.statusCode) || 500;
    const headers = result?.headers && typeof result.headers === 'object' ? result.headers : {};
    res.writeHead(statusCode, headers);
    res.end(typeof result?.body === 'string' ? result.body : JSON.stringify(result?.body ?? {}));
  } catch {
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    }
    res.end(JSON.stringify({ error: 'Kesalahan internal gateway.' }));
  }
});

const port = Number(process.env.PORT || 9000);
server.listen(port, '0.0.0.0');
