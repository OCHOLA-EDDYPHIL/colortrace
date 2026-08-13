import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "@playwright/test";

const packageRoot = fileURLToPath(new URL(".", import.meta.url));
const artifactRoot = path.resolve(packageRoot, "../../.cache/playwright");

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  workers: 2,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  outputDir: path.join(artifactRoot, "results"),
  reporter: [
    ["line"],
    ["html", { open: "never", outputFolder: path.join(artifactRoot, "report") }],
  ],
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "off",
  },
  webServer: {
    command: `"${process.execPath}" node_modules/vite/bin/vite.js --host 127.0.0.1 --port 4173 --strictPort`,
    cwd: packageRoot,
    port: 4173,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
