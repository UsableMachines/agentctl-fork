import crypto, { randomUUID } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import type {
  AgentAdapter,
  AgentSession,
  LaunchOpts,
  LifecycleEvent,
  ListOpts,
  PeekOpts,
  StopOpts,
} from "../core/types.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:18789";

const _require = createRequire(import.meta.url);
const PKG_VERSION: string = (
  _require("../../package.json") as { version: string }
).version;

// --- Device identity helpers ---

/** Ed25519 SPKI DER prefix (RFC 8410) — strip to get raw 32-byte public key */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface DeviceIdentity {
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const spki = crypto
    .createPublicKey(publicKeyPem)
    .export({ type: "spki", format: "der" });
  if (
    spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return spki.subarray(ED25519_SPKI_PREFIX.length);
  }
  return spki;
}

function fingerprintPublicKey(publicKeyPem: string): string {
  const raw = derivePublicKeyRaw(publicKeyPem);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function publicKeyRawBase64Url(publicKeyPem: string): string {
  return base64UrlEncode(derivePublicKeyRaw(publicKeyPem));
}

function signPayload(privateKeyPem: string, payload: string): string {
  const key = crypto.createPrivateKey(privateKeyPem);
  return base64UrlEncode(
    Buffer.from(crypto.sign(null, Buffer.from(payload, "utf8"), key)),
  );
}

function generateDeviceIdentity(): DeviceIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  return {
    deviceId: fingerprintPublicKey(publicKeyPem),
    publicKeyPem,
    privateKeyPem,
  };
}

/** Default identity path: ~/.agentctl/identity/device.json */
function resolveDefaultIdentityPath(): string {
  return path.join(os.homedir(), ".agentctl", "identity", "device.json");
}

/**
 * Load or create agentctl's device identity. Uses its own key pair
 * (separate from OpenClaw's identity at ~/.openclaw/identity/device.json).
 */
export function loadOrCreateDeviceIdentity(
  filePath: string = resolveDefaultIdentityPath(),
): DeviceIdentity {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw);
      if (
        parsed?.version === 1 &&
        typeof parsed.deviceId === "string" &&
        typeof parsed.publicKeyPem === "string" &&
        typeof parsed.privateKeyPem === "string"
      ) {
        // Re-derive deviceId from public key in case it drifted
        const derivedId = fingerprintPublicKey(parsed.publicKeyPem);
        return {
          deviceId: derivedId,
          publicKeyPem: parsed.publicKeyPem,
          privateKeyPem: parsed.privateKeyPem,
        };
      }
    }
  } catch {
    // Fall through to generate new identity
  }

  const identity = generateDeviceIdentity();
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const stored = {
    version: 1,
    deviceId: identity.deviceId,
    publicKeyPem: identity.publicKeyPem,
    privateKeyPem: identity.privateKeyPem,
    createdAtMs: Date.now(),
  };
  fs.writeFileSync(filePath, `${JSON.stringify(stored, null, 2)}\n`, {
    mode: 0o600,
  });
  return identity;
}

// --- Connect params ---

export interface OpenClawAdapterOpts {
  baseUrl?: string; // Default: http://127.0.0.1:18789
  authToken?: string; // Default: process.env.OPENCLAW_GATEWAY_TOKEN ?? process.env.OPENCLAW_WEBHOOK_TOKEN
  /** Device identity for scoped access. Auto-created if not provided. */
  deviceIdentity?: DeviceIdentity | null;
  /** Override for testing — replaces the real WebSocket RPC call */
  rpcCall?: RpcCallFn;
}

/**
 * Shape of a single RPC exchange: send method+params, get back the payload.
 * Injected in tests to avoid a real WebSocket connection.
 */
export type RpcCallFn = (
  method: string,
  params: Record<string, unknown>,
) => Promise<unknown>;

/** Row returned by the gateway's `sessions.list` method */
export interface GatewaySessionRow {
  key: string;
  kind: "direct" | "group" | "global" | "unknown";
  label?: string;
  displayName?: string;
  derivedTitle?: string;
  lastMessagePreview?: string;
  channel?: string;
  updatedAt: number | null;
  sessionId?: string;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  model?: string;
  modelProvider?: string;
}

/** Result envelope from `sessions.list` */
export interface SessionsListResult {
  ts: number;
  path: string;
  count: number;
  defaults: {
    modelProvider: string | null;
    model: string | null;
    contextTokens: number | null;
  };
  sessions: GatewaySessionRow[];
}

/** Single preview entry from `sessions.preview` */
export interface SessionsPreviewEntry {
  key: string;
  status: "ok" | "empty" | "missing" | "error";
  items: Array<{ role: string; text: string }>;
}

/** Result envelope from `sessions.preview` */
export interface SessionsPreviewResult {
  ts: number;
  previews: SessionsPreviewEntry[];
}

/**
 * Build the device auth payload string for signing.
 * Format: v2|deviceId|clientId|clientMode|role|scopes|signedAtMs|token|nonce
 */
export function buildDeviceAuthPayload(params: {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token: string | null;
  nonce: string | null;
}): string {
  const version = params.nonce ? "v2" : "v1";
  const base = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    params.scopes.join(","),
    String(params.signedAtMs),
    params.token ?? "",
  ];
  if (version === "v2") base.push(params.nonce ?? "");
  return base.join("|");
}

/**
 * Build the full `connect` handshake params sent to the gateway.
 * Includes device auth for scoped access when identity is available.
 * Exported so tests can verify the protocol constants.
 */
export function buildConnectParams(
  authToken: string,
  deviceIdentity?: DeviceIdentity | null,
  nonce?: string | null,
) {
  const scopes = ["operator.read"];
  const signedAtMs = Date.now();

  const device = deviceIdentity
    ? (() => {
        const payload = buildDeviceAuthPayload({
          deviceId: deviceIdentity.deviceId,
          clientId: "cli",
          clientMode: "cli",
          role: "operator",
          scopes,
          signedAtMs,
          token: authToken || null,
          nonce: nonce ?? null,
        });
        return {
          id: deviceIdentity.deviceId,
          publicKey: publicKeyRawBase64Url(deviceIdentity.publicKeyPem),
          signature: signPayload(deviceIdentity.privateKeyPem, payload),
          signedAt: signedAtMs,
          nonce: nonce ?? undefined,
        };
      })()
    : undefined;

  return {
    minProtocol: 1,
    maxProtocol: 3,
    client: {
      id: "cli" as const,
      version: PKG_VERSION,
      platform: process.platform,
      mode: "cli" as const,
    },
    role: "operator" as const,
    scopes,
    auth: { token: authToken || null },
    device,
  };
}

/**
 * OpenClaw adapter — reads session data from the OpenClaw gateway via
 * its WebSocket RPC protocol. Falls back gracefully when the gateway
 * is unreachable.
 *
 * Uses Ed25519 device auth for scoped access (operator.read).
 * Device identity is auto-created at ~/.agentctl/identity/device.json.
 */
export class OpenClawAdapter implements AgentAdapter {
  readonly id = "openclaw";
  private readonly baseUrl: string;
  private readonly authToken: string;
  private readonly deviceIdentity: DeviceIdentity | null;
  private readonly rpcCall: RpcCallFn;

  constructor(opts?: OpenClawAdapterOpts) {
    this.baseUrl = opts?.baseUrl || DEFAULT_BASE_URL;
    this.authToken =
      opts?.authToken ||
      process.env.OPENCLAW_GATEWAY_TOKEN ||
      process.env.OPENCLAW_WEBHOOK_TOKEN ||
      "";
    // Device identity: explicit null disables it (for tests), undefined = auto-create
    this.deviceIdentity =
      opts?.deviceIdentity === null
        ? null
        : (opts?.deviceIdentity ?? this.tryLoadDeviceIdentity());
    this.rpcCall = opts?.rpcCall || this.defaultRpcCall.bind(this);
  }

  private tryLoadDeviceIdentity(): DeviceIdentity | null {
    try {
      return loadOrCreateDeviceIdentity();
    } catch {
      // Don't break adapter construction if identity can't be created
      return null;
    }
  }

  async list(opts?: ListOpts): Promise<AgentSession[]> {
    if (!this.authToken) {
      console.warn(
        "Warning: OPENCLAW_GATEWAY_TOKEN is not set — OpenClaw adapter cannot authenticate. " +
          "Set OPENCLAW_GATEWAY_TOKEN (or OPENCLAW_WEBHOOK_TOKEN) to connect to the gateway.",
      );
      return [];
    }

    let result: SessionsListResult;
    try {
      result = (await this.rpcCall("sessions.list", {
        includeDerivedTitles: true,
        includeLastMessage: true,
      })) as SessionsListResult;
    } catch (err) {
      const msg = (err as Error)?.message || "unknown error";
      if (msg.includes("auth") || msg.includes("Auth")) {
        console.warn(
          `Warning: OpenClaw gateway authentication failed: ${msg}. ` +
            "Check that OPENCLAW_GATEWAY_TOKEN (or OPENCLAW_WEBHOOK_TOKEN) is valid.",
        );
      } else {
        console.warn(
          `Warning: OpenClaw gateway unreachable (${msg}). ` +
            `Is the gateway running at ${this.baseUrl}?`,
        );
      }
      return [];
    }

    let sessions = result.sessions.map((row) =>
      this.mapRowToSession(row, result.defaults),
    );

    if (opts?.status) {
      sessions = sessions.filter((s) => s.status === opts.status);
    }

    if (!opts?.all && !opts?.status) {
      sessions = sessions.filter(
        (s) => s.status === "running" || s.status === "idle",
      );
    }

    return sessions;
  }

  async peek(sessionId: string, opts?: PeekOpts): Promise<string> {
    const key = await this.resolveKey(sessionId);
    if (!key) throw new Error(`Session not found: ${sessionId}`);

    const limit = opts?.lines ?? 20;
    let result: SessionsPreviewResult;
    try {
      result = (await this.rpcCall("sessions.preview", {
        keys: [key],
        limit,
        maxChars: 4000,
      })) as SessionsPreviewResult;
    } catch (err) {
      throw new Error(
        `Failed to peek session ${sessionId}: ${(err as Error).message}`,
      );
    }

    const preview = result.previews?.[0];
    if (!preview || preview.status === "missing") {
      throw new Error(`Session not found: ${sessionId}`);
    }

    if (preview.items.length === 0) return "(no messages)";

    const assistantMessages = preview.items
      .filter((item) => item.role === "assistant")
      .map((item) => item.text);

    if (assistantMessages.length === 0) return "(no assistant messages)";

    return assistantMessages.slice(-limit).join("\n---\n");
  }

  async status(sessionId: string): Promise<AgentSession> {
    if (!this.authToken) {
      throw new Error(
        "OPENCLAW_GATEWAY_TOKEN is not set — cannot connect to OpenClaw gateway",
      );
    }

    let result: SessionsListResult;
    try {
      result = (await this.rpcCall("sessions.list", {
        includeDerivedTitles: true,
        search: sessionId,
      })) as SessionsListResult;
    } catch (err) {
      throw new Error(
        `Failed to get status for ${sessionId}: ${(err as Error).message}`,
      );
    }

    const row = result.sessions.find(
      (s) =>
        s.sessionId === sessionId ||
        s.key === sessionId ||
        s.sessionId?.startsWith(sessionId) ||
        s.key.startsWith(sessionId),
    );

    if (!row) throw new Error(`Session not found: ${sessionId}`);

    return this.mapRowToSession(row, result.defaults);
  }

  async launch(_opts: LaunchOpts): Promise<AgentSession> {
    throw new Error("OpenClaw sessions cannot be launched via agentctl");
  }

  async stop(_sessionId: string, _opts?: StopOpts): Promise<void> {
    throw new Error("OpenClaw sessions cannot be stopped via agentctl");
  }

  async resume(sessionId: string, _message: string): Promise<void> {
    throw new Error(
      `Cannot resume OpenClaw session ${sessionId} — use the gateway UI or configured channel`,
    );
  }

  async *events(): AsyncIterable<LifecycleEvent> {
    let knownSessions = new Map<string, AgentSession>();

    const initial = await this.list({ all: true });
    for (const s of initial) {
      knownSessions.set(s.id, s);
    }

    while (true) {
      await sleep(5000);

      let current: AgentSession[];
      try {
        current = await this.list({ all: true });
      } catch {
        continue;
      }

      const currentMap = new Map(current.map((s) => [s.id, s]));

      for (const [id, session] of currentMap) {
        const prev = knownSessions.get(id);
        if (!prev) {
          yield {
            type: "session.started",
            adapter: this.id,
            sessionId: id,
            session,
            timestamp: new Date(),
          };
        } else if (prev.status === "running" && session.status === "stopped") {
          yield {
            type: "session.stopped",
            adapter: this.id,
            sessionId: id,
            session,
            timestamp: new Date(),
          };
        } else if (prev.status === "running" && session.status === "idle") {
          yield {
            type: "session.idle",
            adapter: this.id,
            sessionId: id,
            session,
            timestamp: new Date(),
          };
        }
      }

      knownSessions = currentMap;
    }
  }

  // --- Private helpers ---

  private mapRowToSession(
    row: GatewaySessionRow,
    defaults: SessionsListResult["defaults"],
  ): AgentSession {
    const now = Date.now();
    const updatedAt = row.updatedAt ?? 0;
    const ageMs = now - updatedAt;

    const isActive = updatedAt > 0 && ageMs < 5 * 60 * 1000;

    const model = row.model || defaults.model || undefined;
    const input = row.inputTokens ?? 0;
    const output = row.outputTokens ?? 0;

    return {
      id: row.sessionId || row.key,
      adapter: this.id,
      status: isActive ? "running" : "idle",
      startedAt: updatedAt > 0 ? new Date(updatedAt) : new Date(),
      cwd: undefined,
      model,
      prompt: row.derivedTitle || row.displayName || row.label,
      tokens: input || output ? { in: input, out: output } : undefined,
      meta: {
        key: row.key,
        kind: row.kind,
        channel: row.channel,
        displayName: row.displayName,
        modelProvider: row.modelProvider || defaults.modelProvider,
        lastMessagePreview: row.lastMessagePreview,
      },
    };
  }

  private async resolveKey(sessionId: string): Promise<string | null> {
    if (!this.authToken) {
      throw new Error(
        "OPENCLAW_GATEWAY_TOKEN is not set — cannot connect to OpenClaw gateway",
      );
    }

    let result: SessionsListResult;
    try {
      result = (await this.rpcCall("sessions.list", {
        search: sessionId,
      })) as SessionsListResult;
    } catch (err) {
      throw new Error(
        `Failed to resolve session ${sessionId}: ${(err as Error).message}`,
      );
    }

    const row = result.sessions.find(
      (s) =>
        s.sessionId === sessionId ||
        s.key === sessionId ||
        s.sessionId?.startsWith(sessionId) ||
        s.key.startsWith(sessionId),
    );

    return row?.key ?? null;
  }

  /**
   * Real WebSocket RPC call — connects, performs handshake with device auth,
   * sends one request, reads the response, then disconnects.
   */
  private async defaultRpcCall(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    const { WebSocket } = await import("ws" as string).catch(() => {
      return { WebSocket: globalThis.WebSocket };
    });

    const wsUrl = this.baseUrl.replace(/^http/, "ws");
    const ws = new WebSocket(wsUrl);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error("OpenClaw gateway connection timed out"));
      }, 10_000);

      const reqId = randomUUID();
      let connected = false;

      ws.onopen = () => {
        // Wait for challenge event, then send connect
      };

      ws.onmessage = (event: { data: unknown }) => {
        try {
          const raw =
            typeof event.data === "string" ? event.data : String(event.data);
          const frame = JSON.parse(raw);

          // Step 1: Receive challenge (with nonce), send connect with device auth
          if (frame.type === "event" && frame.event === "connect.challenge") {
            const nonce =
              frame.payload && typeof frame.payload.nonce === "string"
                ? frame.payload.nonce
                : null;
            ws.send(
              JSON.stringify({
                type: "req",
                id: randomUUID(),
                method: "connect",
                params: buildConnectParams(
                  this.authToken,
                  this.deviceIdentity,
                  nonce,
                ),
              }),
            );
            return;
          }

          // Step 2: Receive hello-ok, send actual RPC
          if (frame.type === "res" && frame.ok && !connected) {
            connected = true;
            ws.send(
              JSON.stringify({
                type: "req",
                id: reqId,
                method,
                params,
              }),
            );
            return;
          }

          // Step 3: Receive RPC response
          if (frame.type === "res" && frame.id === reqId) {
            clearTimeout(timeout);
            ws.close();
            if (frame.ok) {
              resolve(frame.payload);
            } else {
              reject(new Error(frame.error?.message || `RPC error: ${method}`));
            }
            return;
          }

          // Auth failure
          if (frame.type === "res" && !frame.ok && !connected) {
            clearTimeout(timeout);
            ws.close();
            reject(
              new Error(frame.error?.message || "OpenClaw gateway auth failed"),
            );
          }
        } catch {
          // Ignore malformed frames
        }
      };

      ws.onerror = (err: unknown) => {
        clearTimeout(timeout);
        reject(
          new Error(
            `OpenClaw gateway error: ${(err as Error)?.message || "connection failed"}`,
          ),
        );
      };

      ws.onclose = () => {
        clearTimeout(timeout);
      };
    });
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
