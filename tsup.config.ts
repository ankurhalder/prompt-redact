import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: {
      index: "src/index.ts",
      cli: "src/cli.ts",
      mcp: "src/mcp/index.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: false,
    clean: true,
    treeshake: true,
    target: "node18",
  },
  {
    entry: { bin: "src/bin.ts" },
    format: ["esm"],
    sourcemap: false,
    target: "node18",
  },
]);
