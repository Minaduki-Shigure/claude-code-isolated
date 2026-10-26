'use strict';
// Regression for GHSA-xjj6-f33q-929c, exercising npm's actual undici copy.
// Only an ephemeral loopback listener is used. No process-level exception
// handler is installed: the vulnerable orphan stream must fail this process.
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const path = require('node:path');
const packageRoot = process.argv[2] || '/usr/local/lib/node_modules/npm/node_modules/undici';
const { fetch, Client } = require(packageRoot);
const { version } = require(path.join(packageRoot, 'package.json'));

async function main () {
  const checks = [];
  const sockets = new Set();
  let badRequests = 0;
  let goodRequests = 0;
  let markBadSocketClosed;
  const badSocketClosed = new Promise(resolve => { markBadSocketClosed = resolve; });
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('error', () => {}); // Server peer errors are unrelated to the client bug.
    socket.on('close', () => sockets.delete(socket));
    socket.once('data', request => {
      if (request.toString('ascii').startsWith('GET /bad ')) {
        badRequests++;
        socket.once('close', markBadSocketClosed);
        // Promise one body byte, but send none before closing. Six encodings
        // trigger the fetch limit while the connection is still incomplete.
        socket.end([
          'HTTP/1.1 200 OK',
          'Content-Length: 1',
          'Content-Encoding: ' + Array(6).fill('gzip').join(', '),
          'Connection: close', '', ''
        ].join('\r\n'));
      } else {
        goodRequests++;
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
      }
    });
  });
  const deadline = setTimeout(() => {
    console.error('undici regression timed out');
    process.exit(2);
  }, 7000);
  let client;
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    client = new Client(origin, { headersTimeout: 2000, bodyTimeout: 2000 });
    await assert.rejects(fetch(origin + '/bad', { dispatcher: client }), error => {
      assert.match(error.cause?.message || '', /content-encoding/);
      return true;
    });
    assert.equal(badRequests, 1);
    checks.push('npm-undici-rejects-excessive-content-encodings');
    await badSocketClosed;
    await new Promise(resolve => setTimeout(resolve, 50));
    checks.push('npm-undici-survives-early-close-without-unhandled-error');
    const response = await fetch(origin + '/ok', { dispatcher: client });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'OK');
    assert.equal(goodRequests, 1);
    checks.push('npm-undici-fetch-still-works-after-rejected-response');
  } finally {
    try {
      if (client) await client.destroy();
      for (const socket of sockets) socket.destroy();
      if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    } finally {
      clearTimeout(deadline);
    }
  }
  console.log(JSON.stringify({ checks, undici_version: version }));
}
main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
