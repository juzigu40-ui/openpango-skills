import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const PROVIDERS = new Set(["email", "github", "twitter", "telegram"]);

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
}

function dbPath() {
  const fromEnv = process.env.OPENPANGO_AGENT_INTEGRATIONS_DB;
  if (fromEnv && fromEnv.trim()) return fromEnv;
  return path.join(os.homedir(), ".openpango", "workspace", "agent_integrations.db");
}

function keyMaterial() {
  const raw = process.env.OPENPANGO_INTEGRATIONS_KEY || "openpango-local-dev-key-change-me";
  return crypto.createHash("sha256").update(raw).digest();
}

function nowIso() {
  return new Date().toISOString();
}

function openDb() {
  const file = dbPath();
  ensureDir(file);
  const db = new DatabaseSync(file);
  db.exec(`
    CREATE TABLE IF NOT EXISTS agent_integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      account_label TEXT NOT NULL DEFAULT 'default',
      encrypted_payload TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(agent_id, provider, account_label)
    );
  `);
  return db;
}

function encryptPayload(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyMaterial(), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted_payload: body.toString("base64"),
    iv: iv.toString("base64"),
    auth_tag: tag.toString("base64"),
  };
}

function decryptPayload(encryptedPayload, ivB64, tagB64) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    keyMaterial(),
    Buffer.from(ivB64, "base64")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const out = Buffer.concat([
    decipher.update(Buffer.from(encryptedPayload, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(out.toString("utf8"));
}

function normalizeIntegration(integration) {
  const provider = String(integration?.provider || "").toLowerCase();
  if (!PROVIDERS.has(provider)) {
    throw new Error(`Unsupported provider: ${provider}`);
  }

  const accountLabel = String(integration?.account_label || "default").trim() || "default";
  const credentials = integration?.credentials;
  if (!credentials || typeof credentials !== "object") {
    throw new Error(`Missing credentials payload for provider=${provider}`);
  }

  return {
    provider,
    account_label: accountLabel,
    credentials,
  };
}

export function upsertAgentIntegrations(agentId, integrations) {
  if (!agentId || typeof agentId !== "string") {
    throw new Error("agentId is required");
  }
  if (!Array.isArray(integrations)) {
    throw new Error("integrations must be an array");
  }

  const db = openDb();
  const ts = nowIso();

  const stmt = db.prepare(`
    INSERT INTO agent_integrations
      (agent_id, provider, account_label, encrypted_payload, iv, auth_tag, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(agent_id, provider, account_label)
    DO UPDATE SET
      encrypted_payload=excluded.encrypted_payload,
      iv=excluded.iv,
      auth_tag=excluded.auth_tag,
      updated_at=excluded.updated_at
  `);

  const saved = [];
  for (const raw of integrations) {
    const normalized = normalizeIntegration(raw);
    const encrypted = encryptPayload(normalized.credentials);
    stmt.run(
      agentId,
      normalized.provider,
      normalized.account_label,
      encrypted.encrypted_payload,
      encrypted.iv,
      encrypted.auth_tag,
      ts,
      ts
    );
    saved.push({ provider: normalized.provider, account_label: normalized.account_label });
  }

  return {
    ok: true,
    agent_id: agentId,
    saved_count: saved.length,
    saved,
  };
}

export function listAgentIntegrations(agentId) {
  if (!agentId || typeof agentId !== "string") {
    throw new Error("agentId is required");
  }
  const db = openDb();
  const rows = db
    .prepare(
      `SELECT provider, account_label, encrypted_payload, iv, auth_tag, updated_at
       FROM agent_integrations WHERE agent_id = ? ORDER BY provider, account_label`
    )
    .all(agentId);

  return rows.map((row) => ({
    provider: row.provider,
    account_label: row.account_label,
    credentials: decryptPayload(row.encrypted_payload, row.iv, row.auth_tag),
    updated_at: row.updated_at,
  }));
}

export function createAgent(payload) {
  const agentId = String(payload?.agent_id || "").trim();
  if (!agentId) throw new Error("agent_id is required");
  const integrations = Array.isArray(payload?.integrations) ? payload.integrations : [];
  return upsertAgentIntegrations(agentId, integrations);
}

export function updateAgent(payload) {
  const agentId = String(payload?.agent_id || "").trim();
  if (!agentId) throw new Error("agent_id is required");
  const integrations = Array.isArray(payload?.integrations) ? payload.integrations : [];
  return upsertAgentIntegrations(agentId, integrations);
}

export const supportedProviders = Array.from(PROVIDERS);
