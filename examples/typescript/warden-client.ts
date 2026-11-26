// A minimal Warden client in TypeScript (Node 23.6+ runs it directly: `node warden-client.ts`).
//
// It does what the Python client does with an agent token: on ONE TCP connection, it makes
// Warden prove its identity (POST /v1/hello) before sending the token or any argument, then
// asks POST /v1/evaluate and only trusts an answer whose Warden-Mac is correct. Anything
// else is a deny. Protocol: docs/design/server-identity.md. Fixed test values:
// docs/identity-test-vectors.json (`node warden-client.ts --vectors FILE` checks them).
//
// Use:  WARDEN_AGENT_TOKEN=wdn_... node warden-client.ts http://127.0.0.1:8000 read_file '{"path": "/a"}'
// It prints the decision as JSON. Copy `evaluate` into your agent; treat every result that
// isn't exactly "allow" as "don't run the tool".

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect, type Socket } from "node:net";

export type Decision = { decision: string; reason: string; approval_id?: string | null };

const hmacHex = (key: Buffer, lines: string[]): string =>
  createHmac("sha256", key).update(lines.join("\n"), "ascii").digest("hex");

export const proofKey = (secret: string): Buffer =>
  createHmac("sha256", Buffer.from(secret, "utf8")).update("warden-server-identity-v1").digest();

export const keyId = (key: Buffer): string =>
  createHash("sha256").update(Buffer.concat([Buffer.from("warden-key-id-v1\n"), key])).digest("hex").slice(0, 32);

export const helloMac = (key: Buffer, nonce: string, server: string, client: string): string =>
  hmacHex(key, ["warden-hello-v1", nonce, server, client]);

export const clientHelloMac = (key: Buffer, nonce: string, server: string, client: string): string =>
  hmacHex(key, ["warden-client-hello-v1", nonce, server, client]);

export function answerMac(key: Buffer, a: {
  nonce: string; server: string; client: string; method: string; target: string;
  requestBody: Buffer; status: number; retryAfter: string; body: Buffer;
}): string {
  return hmacHex(key, [
    "warden-answer-v1", a.nonce, a.server, a.client, a.method,
    Buffer.from(a.target, "ascii").toString("hex"),
    createHash("sha256").update(a.requestBody).digest("hex"),
    String(a.status),
    Buffer.from(a.retryAfter, "latin1").toString("hex"),
    createHash("sha256").update(a.body).digest("hex"),
  ]);
}

const sameMac = (expected: string, received: unknown): boolean =>
  typeof received === "string" && /^[0-9a-f]{64}$/.test(received) &&
  timingSafeEqual(Buffer.from(expected), Buffer.from(received));

// "127.0.0.1:8000", or "[::1]:8000" for IPv6: the same text the server signs.
const address = (host: string | undefined, port: number | undefined): string => {
  if (!host || !port) throw new Error("not a TCP connection");
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
};

type Reply = { status: number; headers: Map<string, string[]>; body: Buffer };

// Reads exactly one HTTP/1.1 response with a Content-Length (what Warden sends).
function readReply(socket: Socket, limit = 65536): Promise<Reply> {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const done = (error?: Error, reply?: Reply) => {
      socket.off("data", onData); socket.off("error", onEnd); socket.off("end", onEnd);
      error ? reject(error) : resolve(reply!);
    };
    const onEnd = () => done(new Error("connection lost"));
    const onData = (chunk: Buffer) => {
      data = Buffer.concat([data, chunk]);
      if (data.length > limit) return done(new Error("answer too large"));
      const end = data.indexOf("\r\n\r\n");
      if (end < 0) return;
      const [statusLine, ...lines] = data.subarray(0, end).toString("latin1").split("\r\n");
      const headers = new Map<string, string[]>();
      for (const line of lines) {
        const i = line.indexOf(":");
        const name = line.slice(0, i).trim().toLowerCase();
        headers.set(name, [...(headers.get(name) ?? []), line.slice(i + 1).trim()]);
      }
      const length = Number(headers.get("content-length")?.[0]);
      if (!Number.isInteger(length)) return done(new Error("no content-length"));
      if (data.length < end + 4 + length) return;
      const status = Number(statusLine.split(" ")[1]);
      done(undefined, { status, headers, body: data.subarray(end + 4, end + 4 + length) });
    };
    socket.on("data", onData); socket.on("error", onEnd); socket.on("end", onEnd);
  });
}

function send(socket: Socket, method: string, target: string, body: Buffer, headers: Record<string, string>) {
  const head = [`${method} ${target} HTTP/1.1`, `Host: ${address(socket.remoteAddress, socket.remotePort)}`,
    "Content-Type: application/json", `Content-Length: ${body.length}`,
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), "", ""].join("\r\n");
  socket.write(Buffer.concat([Buffer.from(head, "latin1"), body]));
}

const deny = (reason: string): Decision => ({ decision: "deny", reason });

/** Ask Warden. Never throws: any failure, or an answer that isn't proven, is a deny. */
export async function evaluate(url: string, token: string, tool: string, args: object,
  timeoutMs = 5000): Promise<Decision> {
  const { hostname, port } = new URL(url);
  const host = hostname.replace(/^\[|\]$/g, "");
  if (!["127.0.0.1", "::1", "localhost"].includes(host)) return deny("Warden must be on this machine");
  const key = proofKey(token);
  const socket = connect({ host, port: Number(port) || 80 });
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error("no answer in time")));
  try {
    await new Promise<void>((ok, fail) => { socket.once("connect", ok); socket.once("error", fail); });
    const server = address(socket.remoteAddress, socket.remotePort);
    const client = address(socket.localAddress, socket.localPort);
    const nonce = randomBytes(32).toString("hex");
    const hello = Buffer.from(JSON.stringify({
      key_id: keyId(key), nonce, client_mac: clientHelloMac(key, nonce, server, client),
    }));
    send(socket, "POST", "/v1/hello", hello, {});
    const proof = await readReply(socket, 4096);
    const mac = proof.status === 200 ? JSON.parse(proof.body.toString("utf8")).mac : null;
    if (!sameMac(helloMac(key, nonce, server, client), mac)) {
      return deny("Warden couldn't prove its identity");
    }
    // Proven: only now the token and the arguments go out, on the same connection.
    const question = Buffer.from(JSON.stringify({ tool, arguments: args }));
    send(socket, "POST", "/v1/evaluate", question, { Authorization: `Bearer ${token}`, "Warden-Nonce": nonce });
    const answer = await readReply(socket);
    const signed = answer.headers.get("warden-mac") ?? [];
    const expected = answerMac(key, {
      nonce, server, client, method: "POST", target: "/v1/evaluate", requestBody: question,
      status: answer.status, retryAfter: (answer.headers.get("retry-after") ?? [""]).join(","),
      body: answer.body,
    });
    if (signed.length !== 1 || !sameMac(expected, signed[0])) {
      return deny("Warden couldn't prove its identity");
    }
    const data = JSON.parse(answer.body.toString("utf8"));
    return typeof data?.decision === "string" ? data : deny("unexpected answer");
  } catch (error) {
    return deny(`Warden unreachable (${(error as Error).message})`);
  } finally {
    socket.destroy();
  }
}

function checkVectors(path: string): void {
  const v = JSON.parse(readFileSync(path, "utf8"));
  const key = proofKey(v.token);
  const got = {
    proof_key_hex: key.toString("hex"),
    key_id: keyId(key),
    hello_mac: helloMac(key, v.nonce, v.server, v.client),
    client_hello_mac: clientHelloMac(key, v.nonce, v.server, v.client),
    answer_mac: answerMac(key, {
      nonce: v.nonce, server: v.server, client: v.client, method: v.answer.method,
      target: v.answer.target, requestBody: Buffer.from(v.answer.request_body),
      status: v.answer.status, retryAfter: v.answer.retry_after, body: Buffer.from(v.answer.body),
    }),
  };
  const want = { ...v, answer_mac: v.answer.mac };
  for (const [name, value] of Object.entries(got)) {
    if (value !== want[name]) throw new Error(`${name}: got ${value}, want ${want[name]}`);
  }
  console.log("all identity test vectors match");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [first, ...rest] = process.argv.slice(2);
  if (first === "--vectors") {
    checkVectors(rest[0]);
  } else {
    const token = process.env.WARDEN_AGENT_TOKEN ?? "";
    const result = token
      ? await evaluate(first, token, rest[0], JSON.parse(rest[1] ?? "{}"))
      : deny("no WARDEN_AGENT_TOKEN");
    console.log(JSON.stringify(result));
  }
}
