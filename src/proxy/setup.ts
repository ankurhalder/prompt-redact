import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { CONFIG_FILENAME, buildVaultFromConfig, loadConfigFile } from "../core/config.js";
import { assertWritableInsideRepository, writeFileInsideRepository } from "../core/fs-safe.js";
import { createVault } from "../core/vault.js";
import type { PromptRedactConfig } from "../types.js";

export interface DoctorCheck {
  id: string;
  ok: boolean;
  detail: string;
}

export interface DoctorResult {
  ok: boolean;
  nodeVersion: string;
  configFile: string | null;
  checks: DoctorCheck[];
  envHints: {
    anthropicBash: string;
    openaiBash: string;
    anthropicPowerShell: string;
    openaiPowerShell: string;
  };
}

export interface SetupResult {
  configPath: string;
  action: "created" | "kept" | "overwritten";
  dryRun: boolean;
  envHints: DoctorResult["envHints"];
}

function checkPortAvailable(port: number, host = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once("error", () => resolve(false));
    tester.once("listening", () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, host);
  });
}

export function buildEnvHints(port = 4790, host = "127.0.0.1"): DoctorResult["envHints"] {
  const base = `http://${host}:${port}`;
  return {
    anthropicBash: `export ANTHROPIC_BASE_URL="${base}"`,
    openaiBash: `export OPENAI_BASE_URL="${base}/v1"`,
    anthropicPowerShell: `$env:ANTHROPIC_BASE_URL = "${base}"`,
    openaiPowerShell: `$env:OPENAI_BASE_URL = "${base}/v1"`,
  };
}

export async function runDoctor(
  cwd: string,
  port = 4790,
  configPath?: string
): Promise<DoctorResult> {
  const checks: DoctorCheck[] = [];
  const major = Number(process.versions.node.split(".")[0]);
  checks.push({
    id: "node-version",
    ok: Number.isFinite(major) && major >= 18,
    detail: `Node ${process.version} (requires >= 18.0.0)`,
  });

  let configFile: string | null = null;
  try {
    const loaded = loadConfigFile(cwd, configPath);
    configFile = loaded.file;
    checks.push({
      id: "config",
      ok: true,
      detail: loaded.file
        ? `Valid JSON config at ${loaded.file}`
        : "No config file found; built-in defaults active",
    });
  } catch (err) {
    checks.push({
      id: "config",
      ok: false,
      detail: (err as Error).message,
    });
  }

  const portFree = await checkPortAvailable(port);
  checks.push({
    id: "proxy-port",
    ok: portFree,
    detail: portFree
      ? `Port ${port} on 127.0.0.1 is available`
      : `Port ${port} on 127.0.0.1 is already in use`,
  });

  // Generated at runtime so the published bundle contains no secret-shaped
  // literal that downstream secret scanners would flag.
  const sample = `sk-proj-doctor${crypto.randomBytes(12).toString("hex")}`;
  let roundTripOk = false;
  try {
    const vault = buildVaultFromConfig(cwd, {
      mode: "ephemeral",
      source: "doctor",
      ...(configPath === undefined ? {} : { configPath }),
    }).vault;
    const red = vault.redact(`token=${sample}`);
    const restored = vault.rehydrate(red.text);
    roundTripOk = !red.text.includes(sample) && restored === `token=${sample}`;
  } catch {
    const fallbackVault = createVault({ mode: "ephemeral" });
    const red = fallbackVault.redact(`token=${sample}`);
    roundTripOk = !red.text.includes(sample) && fallbackVault.rehydrate(red.text) === `token=${sample}`;
  }
  checks.push({
    id: "vault-roundtrip",
    ok: roundTripOk,
    detail: roundTripOk
      ? "In-memory redaction and rehydration round-trip passed with zero leak"
      : "In-memory redaction self-test failed",
  });

  return {
    ok: checks.every((c) => c.ok),
    nodeVersion: process.version,
    configFile,
    checks,
    envHints: buildEnvHints(port),
  };
}

export function defaultConfigObject(): PromptRedactConfig {
  return {
    tokenPrefix: "redact",
    maxEntries: 1024,
    overflowPolicy: "hash",
    mode: "session",
    entropy: {
      enabled: false,
      threshold: 4.2,
      minLength: 24,
    },
    allowlist: [],
    customPatterns: [],
    excludePaths: ["node_modules", ".git", "dist"],
    exec: {
      enabled: false,
      allowCommands: [],
    },
  };
}

export function runSetup(
  cwd: string,
  options: { force?: boolean; port?: number; dryRun?: boolean } = {}
): SetupResult {
  const configPath = path.join(cwd, CONFIG_FILENAME);
  const exists = fs.existsSync(configPath);
  let action: SetupResult["action"] = "kept";
  if (!exists || options.force) {
    action = exists ? "overwritten" : "created";
    if (!options.dryRun) {
      assertWritableInsideRepository(cwd, configPath, "Refusing to write config");
      writeFileInsideRepository(
        cwd,
        configPath,
        `${JSON.stringify(defaultConfigObject(), null, 2)}\n`,
        "Refusing to write config"
      );
    }
  }
  return {
    configPath,
    action,
    dryRun: options.dryRun === true,
    envHints: buildEnvHints(options.port ?? 4790),
  };
}
