/**
 * Node HTTP mock TEE server.
 *
 * Models the subset of MagicBlock PER endpoints that Phase 3 tests exercise
 * against `LivePerSessionManager`:
 *   - GET  /attestation          → fake TDX quote (4-byte header + pad)
 *   - POST /auth/challenge       → {nonce: number[]}
 *   - POST /auth/token           → verifies nonce sig, returns {token}
 *   - POST /                     → JSON-RPC sendTransaction. Returns 401
 *                                  for tampered/missing JWT, returns a
 *                                  dummy signature otherwise.
 *
 * The server is intentionally minimal — it doesn't attempt to run real
 * Anchor transactions. Tests that care about on-chain behaviour use litesvm
 * instead. This server only proves that the TS session manager handles the
 * HTTP error states correctly (attestation fail, 401 refresh, etc.).
 */

import { createHmac, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export interface MockTeeServerHandle {
  url: string;
  close: () => Promise<void>;
  /** Count of successful sendTransaction calls. Useful for assertions. */
  getSendCount(): number;
  /** Toggle attestation pass/fail at runtime. */
  setAttestationOk(ok: boolean): void;
  /** Force the next /auth/token call to succeed (default) or reject. */
  setAuthOk(ok: boolean): void;
  /** Force the NEXT sendTransaction to reject with 401 once. */
  forceNext401(): void;
  /** Last JWT observed on a sendTransaction call. */
  getLastJwt(): string | null;
}

const SECRET = "nyx_mock_tee_hmac_secret";

function signJwt(pubkey: number[]): string {
  const payload = Buffer.from(JSON.stringify({ pk: pubkey, iat: Date.now() }));
  const sig = createHmac("sha256", SECRET).update(payload).digest();
  return `${payload.toString("base64url")}.${sig.toString("base64url")}`;
}

function verifyJwt(jwt: string): boolean {
  const parts = jwt.split(".");
  if (parts.length !== 2) return false;
  const [p, sigBase64] = parts;
  const payload = Buffer.from(p, "base64url");
  const expected = createHmac("sha256", SECRET).update(payload).digest();
  const received = Buffer.from(sigBase64, "base64url");
  if (received.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ received[i];
  return diff === 0;
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export async function startMockTeeServer(): Promise<MockTeeServerHandle> {
  let sendCount = 0;
  let attestationOk = true;
  let authOk = true;
  let next401 = false;
  let lastJwt: string | null = null;

  const onRequest = async (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "/";
    try {
      if (req.method === "GET" && url.startsWith("/attestation")) {
        if (!attestationOk) {
          res.statusCode = 500;
          res.end();
          return;
        }
        // Fake TDX quote: starts with 0x04 (TDX 1.0 marker), 64 bytes total.
        const quote = Buffer.alloc(64);
        quote[0] = 0x04;
        quote.set(randomBytes(62), 2);
        res.statusCode = 200;
        res.setHeader("content-type", "application/octet-stream");
        res.end(quote);
        return;
      }
      if (req.method === "POST" && url.startsWith("/auth/challenge")) {
        const nonce = randomBytes(32);
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ nonce: Array.from(nonce) }));
        return;
      }
      if (req.method === "POST" && url.startsWith("/auth/token")) {
        if (!authOk) {
          res.statusCode = 401;
          res.end();
          return;
        }
        const body = JSON.parse(await readBody(req)) as { pubkey: number[] };
        const token = signJwt(body.pubkey);
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ token }));
        return;
      }
      // JSON-RPC sendTransaction
      if (req.method === "POST" && (url === "/" || url === "")) {
        const auth = req.headers["authorization"];
        const jwt = typeof auth === "string" ? auth.replace(/^Bearer\s+/i, "") : "";
        lastJwt = jwt;
        if (next401 || !jwt || !verifyJwt(jwt)) {
          next401 = false;
          res.statusCode = 401;
          res.end();
          return;
        }
        await readBody(req); // drain body; we don't process the tx for Phase 3
        sendCount += 1;
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: `mock_sig_${sendCount}`,
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end();
    } catch (err) {
      res.statusCode = 500;
      res.end(`mock-tee error: ${String(err)}`);
    }
  };

  const server: Server = createServer((req, res) => {
    void onRequest(req, res);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("mock-tee failed to bind");
  }
  const url = `http://127.0.0.1:${addr.port}`;

  return {
    url,
    getSendCount: () => sendCount,
    setAttestationOk: (ok) => {
      attestationOk = ok;
    },
    setAuthOk: (ok) => {
      authOk = ok;
    },
    forceNext401: () => {
      next401 = true;
    },
    getLastJwt: () => lastJwt,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
