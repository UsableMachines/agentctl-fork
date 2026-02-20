import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildConnectParams,
  buildDeviceAuthPayload,
  loadOrCreateDeviceIdentity,
  OpenClawAdapter,
  type RpcCallFn,
  type SessionsListResult,
  type SessionsPreviewResult,
} from "./openclaw.js";

const now = Date.now();
const fiveMinAgo = now - 5 * 60 * 1000 + 30_000; // just under 5 min ago — "running"
const hourAgo = now - 60 * 60 * 1000; // 1 hour ago — "idle"

// Save and clear env vars that affect adapter construction
const ENV_KEYS = ["OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_WEBHOOK_TOKEN"] as const;
let savedEnv: Record<string, string | undefined>;

function makeListResult(
  sessions: SessionsListResult["sessions"] = [],
): SessionsListResult {
  return {
    ts: now,
    path: "/mock/store.json",
    count: sessions.length,
    defaults: {
      modelProvider: "anthropic",
      model: "claude-sonnet-4-5-20250929",
      contextTokens: 200_000,
    },
    sessions,
  };
}

function makePreviewResult(
  previews: SessionsPreviewResult["previews"] = [],
): SessionsPreviewResult {
  return { ts: now, previews };
}

function makeMockRpc(
  handlers: Record<string, (params: Record<string, unknown>) => unknown>,
): RpcCallFn {
  return async (method, params) => {
    const handler = handlers[method];
    if (!handler) throw new Error(`Unexpected RPC method: ${method}`);
    return handler(params);
  };
}

// --- Tests ---

describe("OpenClawAdapter", () => {
  beforeEach(() => {
    savedEnv = {};
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (savedEnv[key] !== undefined) {
        process.env[key] = savedEnv[key];
      } else {
        delete process.env[key];
      }
    }
  });

  it("has correct id", () => {
    const adapter = new OpenClawAdapter({
      rpcCall: makeMockRpc({}),
      deviceIdentity: null,
    });
    expect(adapter.id).toBe("openclaw");
  });

  describe("list()", () => {
    it("returns empty array with warning when token is missing", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const adapter = new OpenClawAdapter({
        authToken: "",
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      const sessions = await adapter.list();
      expect(sessions).toEqual([]);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("OPENCLAW_GATEWAY_TOKEN is not set"),
      );
      warnSpy.mockRestore();
    });

    it("returns empty array with warning when gateway is unreachable", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: async () => {
          throw new Error("connection refused");
        },
        deviceIdentity: null,
      });
      const sessions = await adapter.list();
      expect(sessions).toEqual([]);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("OpenClaw gateway unreachable"),
      );
      warnSpy.mockRestore();
    });

    it("warns about auth failure specifically", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const adapter = new OpenClawAdapter({
        authToken: "bad-token",
        rpcCall: async () => {
          throw new Error("OpenClaw gateway auth failed");
        },
        deviceIdentity: null,
      });
      const sessions = await adapter.list();
      expect(sessions).toEqual([]);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("OPENCLAW_GATEWAY_TOKEN"),
      );
      warnSpy.mockRestore();
    });

    it("returns mapped sessions from gateway", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:main",
                kind: "direct",
                label: "main",
                displayName: "Main Session",
                derivedTitle: "Help me with code",
                updatedAt: fiveMinAgo,
                sessionId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                inputTokens: 1000,
                outputTokens: 500,
                model: "claude-opus-4-6",
                modelProvider: "anthropic",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const sessions = await adapter.list({ all: true });
      expect(sessions).toHaveLength(1);
      expect(sessions[0].id).toBe("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
      expect(sessions[0].adapter).toBe("openclaw");
      expect(sessions[0].status).toBe("running");
      expect(sessions[0].model).toBe("claude-opus-4-6");
      expect(sessions[0].tokens).toEqual({ in: 1000, out: 500 });
      expect(sessions[0].prompt).toBe("Help me with code");
      expect(sessions[0].meta.key).toBe("agent:jarvis:main");
    });

    it("classifies old sessions as idle", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:old-session",
                kind: "direct",
                updatedAt: hourAgo,
                sessionId: "old-session-id",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const sessions = await adapter.list({ all: true });
      expect(sessions).toHaveLength(1);
      expect(sessions[0].status).toBe("idle");
    });

    it("default list shows running and idle sessions", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:active",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "active-id",
              },
              {
                key: "agent:jarvis:old",
                kind: "direct",
                updatedAt: hourAgo,
                sessionId: "old-id",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const sessions = await adapter.list();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].status).toBe("running");
      expect(sessions[1].status).toBe("idle");
    });

    it("filters by status", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:active",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "active-id",
              },
              {
                key: "agent:jarvis:idle",
                kind: "direct",
                updatedAt: hourAgo,
                sessionId: "idle-id",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const idle = await adapter.list({ status: "idle" });
      expect(idle).toHaveLength(1);
      expect(idle[0].id).toBe("idle-id");

      const running = await adapter.list({ status: "running" });
      expect(running).toHaveLength(1);
      expect(running[0].id).toBe("active-id");
    });

    it("uses session key as id when sessionId is missing", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:no-session-id",
                kind: "direct",
                updatedAt: fiveMinAgo,
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const sessions = await adapter.list({ all: true });
      expect(sessions[0].id).toBe("agent:jarvis:no-session-id");
    });

    it("uses default model when row has no model", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:test",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "test-id",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const sessions = await adapter.list({ all: true });
      expect(sessions[0].model).toBe("claude-sonnet-4-5-20250929");
    });
  });

  describe("peek()", () => {
    it("returns assistant messages from preview", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:peek-test",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "peek-session-id",
              },
            ]),
          "sessions.preview": () =>
            makePreviewResult([
              {
                key: "agent:jarvis:peek-test",
                status: "ok" as const,
                items: [
                  { role: "user", text: "Hello" },
                  { role: "assistant", text: "Hi there!" },
                  { role: "user", text: "How are you?" },
                  { role: "assistant", text: "I'm doing well." },
                ],
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const output = await adapter.peek("peek-session-id");
      expect(output).toContain("Hi there!");
      expect(output).toContain("I'm doing well.");
      expect(output).not.toContain("Hello");
    });

    it("respects line limit", async () => {
      const items: Array<{ role: string; text: string }> = [];
      for (let i = 0; i < 10; i++) {
        items.push({ role: "assistant", text: `Message ${i}` });
      }

      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:limit-test",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "limit-session-id",
              },
            ]),
          "sessions.preview": () =>
            makePreviewResult([
              {
                key: "agent:jarvis:limit-test",
                status: "ok" as const,
                items,
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const output = await adapter.peek("limit-session-id", { lines: 3 });
      expect(output).toContain("Message 7");
      expect(output).toContain("Message 8");
      expect(output).toContain("Message 9");
      expect(output).not.toContain("Message 6");
    });

    it("throws for unknown session", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () => makeListResult([]),
        }),
        deviceIdentity: null,
      });

      await expect(adapter.peek("nonexistent")).rejects.toThrow(
        "Session not found",
      );
    });

    it("supports prefix matching", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:prefix-test",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "abcdef12-3456-7890-abcd-ef1234567890",
              },
            ]),
          "sessions.preview": () =>
            makePreviewResult([
              {
                key: "agent:jarvis:prefix-test",
                status: "ok" as const,
                items: [{ role: "assistant", text: "Found by prefix!" }],
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const output = await adapter.peek("abcdef12");
      expect(output).toContain("Found by prefix!");
    });
  });

  describe("status()", () => {
    it("throws when token is missing", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "",
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      await expect(adapter.status("some-id")).rejects.toThrow(
        "OPENCLAW_GATEWAY_TOKEN is not set",
      );
    });

    it("returns session details", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:status-test",
                kind: "direct",
                displayName: "Status Test",
                updatedAt: fiveMinAgo,
                sessionId: "status-session-id",
                inputTokens: 500,
                outputTokens: 200,
                model: "claude-opus-4-6",
                modelProvider: "anthropic",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const session = await adapter.status("status-session-id");
      expect(session.id).toBe("status-session-id");
      expect(session.adapter).toBe("openclaw");
      expect(session.status).toBe("running");
      expect(session.model).toBe("claude-opus-4-6");
      expect(session.tokens).toEqual({ in: 500, out: 200 });
    });

    it("throws for unknown session", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () => makeListResult([]),
        }),
        deviceIdentity: null,
      });

      await expect(adapter.status("nonexistent")).rejects.toThrow(
        "Session not found",
      );
    });

    it("supports prefix matching", async () => {
      const adapter = new OpenClawAdapter({
        authToken: "test-token",
        rpcCall: makeMockRpc({
          "sessions.list": () =>
            makeListResult([
              {
                key: "agent:jarvis:prefix-status",
                kind: "direct",
                updatedAt: fiveMinAgo,
                sessionId: "abcdef12-9999-9999-9999-999999999999",
                model: "claude-opus-4-6",
              },
            ]),
        }),
        deviceIdentity: null,
      });

      const session = await adapter.status("abcdef12");
      expect(session.id).toBe("abcdef12-9999-9999-9999-999999999999");
    });
  });

  describe("buildConnectParams()", () => {
    it("uses correct client.id and protocol version", () => {
      const params = buildConnectParams("test-token");
      expect(params.client.id).toBe("cli");
      expect(params.maxProtocol).toBe(3);
      expect(params.minProtocol).toBe(1);
      expect(params.role).toBe("operator");
      expect(params.scopes).toEqual(["operator.read"]);
    });

    it("passes auth token", () => {
      const params = buildConnectParams("my-secret-token");
      expect(params.auth.token).toBe("my-secret-token");
    });

    it("passes null when token is empty", () => {
      const params = buildConnectParams("");
      expect(params.auth.token).toBeNull();
    });

    it("includes platform and version", () => {
      const params = buildConnectParams("tok");
      expect(params.client.platform).toBe(process.platform);
      expect(params.client.version).toBeTruthy();
      expect(params.client.mode).toBe("cli");
    });

    it("includes device auth when identity is provided", () => {
      const identity = {
        deviceId: "test-device-id",
        publicKeyPem: generateTestKeyPair().publicKeyPem,
        privateKeyPem: generateTestKeyPair().privateKeyPem,
      };
      const params = buildConnectParams("tok", identity, "test-nonce");
      expect(params.device).toBeDefined();
      expect(params.device?.id).toBe("test-device-id");
      expect(params.device?.publicKey).toBeTruthy();
      expect(params.device?.signature).toBeTruthy();
      expect(params.device?.nonce).toBe("test-nonce");
    });

    it("omits device when identity is null", () => {
      const params = buildConnectParams("tok", null);
      expect(params.device).toBeUndefined();
    });
  });

  describe("buildDeviceAuthPayload()", () => {
    it("builds v2 payload with nonce", () => {
      const payload = buildDeviceAuthPayload({
        deviceId: "dev123",
        clientId: "cli",
        clientMode: "cli",
        role: "operator",
        scopes: ["operator.read"],
        signedAtMs: 1700000000000,
        token: "tok123",
        nonce: "nonce456",
      });
      expect(payload).toBe(
        "v2|dev123|cli|cli|operator|operator.read|1700000000000|tok123|nonce456",
      );
    });

    it("builds v1 payload without nonce", () => {
      const payload = buildDeviceAuthPayload({
        deviceId: "dev123",
        clientId: "cli",
        clientMode: "cli",
        role: "operator",
        scopes: ["operator.read"],
        signedAtMs: 1700000000000,
        token: "tok123",
        nonce: null,
      });
      expect(payload).toBe(
        "v1|dev123|cli|cli|operator|operator.read|1700000000000|tok123",
      );
    });

    it("handles empty token", () => {
      const payload = buildDeviceAuthPayload({
        deviceId: "dev",
        clientId: "cli",
        clientMode: "cli",
        role: "operator",
        scopes: [],
        signedAtMs: 0,
        token: null,
        nonce: null,
      });
      expect(payload).toBe("v1|dev|cli|cli|operator||0|");
    });
  });

  describe("loadOrCreateDeviceIdentity()", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentctl-test-"));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("creates a new identity file when none exists", () => {
      const filePath = path.join(tmpDir, "identity", "device.json");
      const identity = loadOrCreateDeviceIdentity(filePath);

      expect(identity.deviceId).toBeTruthy();
      expect(identity.publicKeyPem).toContain("BEGIN PUBLIC KEY");
      expect(identity.privateKeyPem).toContain("BEGIN PRIVATE KEY");
      expect(fs.existsSync(filePath)).toBe(true);

      // File permissions should be 0o600
      const stat = fs.statSync(filePath);
      expect(stat.mode & 0o777).toBe(0o600);
    });

    it("loads existing identity", () => {
      const filePath = path.join(tmpDir, "device.json");
      const first = loadOrCreateDeviceIdentity(filePath);
      const second = loadOrCreateDeviceIdentity(filePath);

      expect(second.deviceId).toBe(first.deviceId);
      expect(second.publicKeyPem).toBe(first.publicKeyPem);
    });

    it("deviceId is SHA-256 fingerprint of public key", () => {
      const filePath = path.join(tmpDir, "device.json");
      const identity = loadOrCreateDeviceIdentity(filePath);

      // Derive expected fingerprint
      const spki = crypto
        .createPublicKey(identity.publicKeyPem)
        .export({ type: "spki", format: "der" });
      const raw = spki.subarray(spki.length - 32); // Ed25519 raw key is last 32 bytes
      const expected = crypto.createHash("sha256").update(raw).digest("hex");
      expect(identity.deviceId).toBe(expected);
    });
  });

  describe("auth token resolution", () => {
    it("prefers OPENCLAW_GATEWAY_TOKEN over OPENCLAW_WEBHOOK_TOKEN", () => {
      process.env.OPENCLAW_GATEWAY_TOKEN = "gateway-token";
      process.env.OPENCLAW_WEBHOOK_TOKEN = "webhook-token";
      const adapter = new OpenClawAdapter({
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      adapter.list();
      expect(warnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("is not set"),
      );
      warnSpy.mockRestore();
    });

    it("falls back to OPENCLAW_WEBHOOK_TOKEN", () => {
      process.env.OPENCLAW_WEBHOOK_TOKEN = "webhook-token";
      const adapter = new OpenClawAdapter({
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      adapter.list();
      expect(warnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("is not set"),
      );
      warnSpy.mockRestore();
    });

    it("explicit authToken takes priority over env vars", () => {
      process.env.OPENCLAW_GATEWAY_TOKEN = "env-token";
      const adapter = new OpenClawAdapter({
        authToken: "explicit-token",
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      adapter.list();
      expect(warnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("is not set"),
      );
      warnSpy.mockRestore();
    });
  });

  describe("unsupported operations", () => {
    it("launch throws", async () => {
      const adapter = new OpenClawAdapter({
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      await expect(
        adapter.launch({ adapter: "openclaw", prompt: "test" }),
      ).rejects.toThrow("cannot be launched");
    });

    it("stop throws", async () => {
      const adapter = new OpenClawAdapter({
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      await expect(adapter.stop("some-id")).rejects.toThrow(
        "cannot be stopped",
      );
    });

    it("resume throws", async () => {
      const adapter = new OpenClawAdapter({
        rpcCall: makeMockRpc({}),
        deviceIdentity: null,
      });
      await expect(adapter.resume("some-id", "msg")).rejects.toThrow(
        "Cannot resume",
      );
    });
  });
});

// --- Test helpers ---

function generateTestKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}
