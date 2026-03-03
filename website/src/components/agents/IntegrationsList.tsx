"use client";

import { useMemo } from "react";

type Provider = "email" | "github" | "twitter" | "telegram";

export type IntegrationItem = {
  provider: Provider;
  account_label?: string;
  credentials: Record<string, string>;
};

type Props = {
  value: IntegrationItem[];
  onChange: (next: IntegrationItem[]) => void;
};

const providerFields: Record<Provider, Array<{ key: string; label: string; type?: string }>> = {
  email: [
    { key: "email", label: "Email" },
    { key: "password", label: "Password", type: "password" },
    { key: "imap_host", label: "IMAP Host" },
    { key: "smtp_host", label: "SMTP Host" },
  ],
  github: [
    { key: "username", label: "GitHub Username" },
    { key: "token", label: "GitHub Token", type: "password" },
  ],
  twitter: [
    { key: "api_key", label: "API Key" },
    { key: "api_secret", label: "API Secret", type: "password" },
    { key: "access_token", label: "Access Token", type: "password" },
    { key: "access_secret", label: "Access Secret", type: "password" },
  ],
  telegram: [
    { key: "bot_token", label: "Bot Token", type: "password" },
    { key: "chat_id", label: "Chat ID" },
  ],
};

const providers: Provider[] = ["email", "github", "twitter", "telegram"];

function emptyIntegration(provider: Provider): IntegrationItem {
  const credentials: Record<string, string> = {};
  for (const f of providerFields[provider]) credentials[f.key] = "";
  return { provider, account_label: "default", credentials };
}

export default function IntegrationsList({ value, onChange }: Props) {
  const byProvider = useMemo(() => {
    const map: Partial<Record<Provider, IntegrationItem>> = {};
    for (const item of value) map[item.provider] = item;
    return map;
  }, [value]);

  const update = (provider: Provider, patch: Partial<IntegrationItem>) => {
    const next = [...value];
    const idx = next.findIndex((x) => x.provider === provider);
    if (idx === -1) {
      next.push({ ...emptyIntegration(provider), ...patch, provider });
    } else {
      next[idx] = { ...next[idx], ...patch, provider };
    }
    onChange(next);
  };

  const remove = (provider: Provider) => {
    onChange(value.filter((x) => x.provider !== provider));
  };

  return (
    <div className="space-y-4">
      {providers.map((provider) => {
        const selected = byProvider[provider] ?? null;
        const enabled = !!selected;
        return (
          <div key={provider} className="rounded-xl border border-white/10 p-4 bg-black/20">
            <div className="flex items-center justify-between mb-3">
              <div className="font-medium text-white capitalize">{provider}</div>
              {!enabled ? (
                <button
                  type="button"
                  onClick={() => update(provider, emptyIntegration(provider))}
                  className="text-xs px-2 py-1 rounded bg-emerald-500/20 text-emerald-300"
                >
                  Enable
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => remove(provider)}
                  className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-300"
                >
                  Remove
                </button>
              )}
            </div>

            {enabled && selected && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="text-xs text-zinc-400">
                  Account Label
                  <input
                    className="mt-1 w-full rounded border border-white/10 bg-black/30 px-2 py-1 text-sm text-white"
                    value={selected.account_label ?? "default"}
                    onChange={(e) => update(provider, { account_label: e.target.value })}
                  />
                </label>

                {providerFields[provider].map((field) => (
                  <label key={field.key} className="text-xs text-zinc-400">
                    {field.label}
                    <input
                      type={field.type ?? "text"}
                      className="mt-1 w-full rounded border border-white/10 bg-black/30 px-2 py-1 text-sm text-white"
                      value={selected.credentials?.[field.key] ?? ""}
                      onChange={(e) =>
                        update(provider, {
                          credentials: {
                            ...(selected.credentials || {}),
                            [field.key]: e.target.value,
                          },
                        })
                      }
                    />
                  </label>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
