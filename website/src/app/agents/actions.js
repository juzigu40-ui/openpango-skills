"use server";

import {
  createAgent as createAgentCore,
  updateAgent as updateAgentCore,
  listAgentIntegrations,
  supportedProviders,
} from "@/lib/agent_integrations_db";

function validateIntegrations(integrations) {
  if (!Array.isArray(integrations)) {
    throw new Error("integrations must be an array");
  }
  for (const entry of integrations) {
    const provider = String(entry?.provider || "").toLowerCase();
    if (!supportedProviders.includes(provider)) {
      throw new Error(`provider not supported: ${provider}`);
    }
    if (!entry?.credentials || typeof entry.credentials !== "object") {
      throw new Error(`credentials missing for provider: ${provider}`);
    }
  }
}

export async function createAgent(input) {
  const payload = input || {};
  validateIntegrations(payload.integrations || []);
  return createAgentCore(payload);
}

export async function updateAgent(input) {
  const payload = input || {};
  validateIntegrations(payload.integrations || []);
  return updateAgentCore(payload);
}

export async function getAgentIntegrations(agentId) {
  return listAgentIntegrations(agentId);
}
