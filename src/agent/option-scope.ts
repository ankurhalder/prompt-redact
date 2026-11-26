export type CommandName =
  | "proxy"
  | "mcp"
  | "serve"
  | "scan"
  | "verify"
  | "setup"
  | "doctor"
  | "skill"
  | "describe";

export const COMMAND_OPTION_SCOPE: Record<CommandName, readonly string[]> = {
  proxy: [
    "cwd",
    "config",
    "no-config",
    "host",
    "port",
    "token",
    "upstream",
    "anthropic-upstream",
    "openai-upstream",
    "dry-run",
    "max-entries",
    "overflow-policy",
    "mode",
    "format",
    "help",
    "version",
  ],
  mcp: [
    "cwd",
    "config",
    "no-config",
    "http",
    "host",
    "port",
    "token",
    "no-auth",
    "allow-origin",
    "max-entries",
    "overflow-policy",
    "help",
    "version",
  ],
  serve: [
    "cwd",
    "config",
    "no-config",
    "host",
    "port",
    "token",
    "no-auth",
    "allow-origin",
    "help",
    "version",
  ],
  scan: [
    "cwd",
    "config",
    "no-config",
    "staged",
    "out-dir",
    "sarif",
    "format",
    "help",
    "version",
  ],
  verify: [
    "cwd",
    "config",
    "no-config",
    "staged",
    "stdin",
    "hook",
    "sarif",
    "out-dir",
    "format",
    "help",
    "version",
  ],
  setup: [
    "cwd",
    "port",
    "force",
    "dry-run",
    "autopilot",
    "format",
    "help",
    "version",
  ],
  doctor: [
    "cwd",
    "config",
    "port",
    "format",
    "help",
    "version",
  ],
  skill: [
    "cwd",
    "install",
    "target",
    "track",
    "format",
    "help",
    "version",
  ],
  describe: [
    "format",
    "help",
    "version",
  ],
};

export function commandsForOption(optionName: string): CommandName[] {
  return (Object.keys(COMMAND_OPTION_SCOPE) as CommandName[]).filter((command) =>
    COMMAND_OPTION_SCOPE[command].includes(optionName)
  );
}

export function optionAppliesTo(optionName: string): string {
  const owners = commandsForOption(optionName);
  if (owners.length === Object.keys(COMMAND_OPTION_SCOPE).length) return "all commands";
  return owners.join(", ");
}
