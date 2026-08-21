import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { readFile } from "node:fs/promises";

const root = fileURLToPath(new URL("../", import.meta.url));
const wrangler = fileURLToPath(new URL("../node_modules/.bin/wrangler", import.meta.url));
const port = await reserveLoopbackPort();
const origin = `http://127.0.0.1:${port}`;
const output = [];
const fixture = JSON.parse(
  await readFile(
    new URL("../test/fixtures/release-candidate-stream-http-boundary-v1.json", import.meta.url),
    "utf8",
  ),
);
const child = spawn(
  wrangler,
  [
    "dev",
    "--config",
    "wrangler.candidate-stream.test.jsonc",
    "--ip",
    "127.0.0.1",
    "--local",
    "--log-level",
    "none",
    "--port",
    String(port),
    "--show-interactive-dev-session=false",
  ],
  {
    cwd: root,
    env: { ...process.env, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  },
);
child.stdout.on("data", (chunk) => output.push(String(chunk)));
child.stderr.on("data", (chunk) => output.push(String(chunk)));

try {
  const response = await waitForWorker(`${origin}/success`, child, output);
  assert.equal(response.status, fixture.status);
  for (const [name, expected] of Object.entries(fixture.headers)) {
    assert.equal(response.headers.get(name), expected, name);
  }
  for (const name of fixture.required_opaque_headers) {
    assert.ok(response.headers.get(name), name);
  }
  for (const name of fixture.forbidden_response_headers_absent) {
    assert.equal(response.headers.get(name), null, name);
  }
  const body = new Uint8Array(await response.arrayBuffer());
  assert.equal(body.byteLength, fixture.body.byte_length);
  assert.equal(Buffer.from(body).toString("hex"), fixture.body.hex);
  assert.equal(`sha256:${createHash("sha256").update(body).digest("hex")}`, fixture.body.sha256);

  for (const path of ["short", "long", "abort", "fragmented", "empty", "stall"]) {
    await assert.rejects(readBody(`${origin}/${path}`));
  }
  process.stdout.write("candidate stream HTTP boundary: 7/7 PASS\n");
} finally {
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function readBody(url) {
  const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5_000) });
  return response.arrayBuffer();
}

async function waitForWorker(url, processHandle, logs) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (processHandle.exitCode !== null) {
      throw new Error(`Wrangler exited early (${processHandle.exitCode}): ${logs.join("")}`);
    }
    try {
      return await fetch(url, { redirect: "error", signal: AbortSignal.timeout(1_000) });
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  throw new Error(`Wrangler did not become ready: ${logs.join("")}`);
}

function reserveLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("failed to reserve a loopback port"));
        return;
      }
      server.close((error) => {
        if (error) reject(error);
        else resolve(address.port);
      });
    });
  });
}
