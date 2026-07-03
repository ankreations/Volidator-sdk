import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "middleware/next": "src/middleware/next.ts",
    "plugins/clerk": "src/plugins/clerk.ts",
    "plugins/universal": "src/plugins/universal.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "es2020",
  tsconfig: "./tsconfig.json",
});
