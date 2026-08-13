import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
  input: "../contracts/openapi.json",
  output: {
    path: "src/generated",
    clean: true,
    postProcess: ["biome:format"],
  },
  plugins: [
    {
      name: "@hey-api/client-fetch",
    },
    {
      name: "@hey-api/typescript",
    },
    {
      name: "@hey-api/sdk",
      client: "@hey-api/client-fetch",
      operations: {
        nesting: "operationId",
        strategy: "flat",
      },
      paramsStructure: "flat",
      responseStyle: "data",
    },
  ],
});
