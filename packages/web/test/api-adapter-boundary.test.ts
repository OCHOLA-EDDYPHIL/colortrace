import { describe, expect, it } from "vitest";

import { createIncidentReadAdapter } from "../src/api-adapter.ts";

describe("browser API authority boundary", () => {
  it("does not expose simulator execution admission", () => {
    const adapter = createIncidentReadAdapter({ baseUrl: "https://web.test" });

    expect(adapter).not.toHaveProperty("admitSimulatorAction");
    expect(Object.keys(adapter)).not.toContain("simulatorActions");
  });
});
