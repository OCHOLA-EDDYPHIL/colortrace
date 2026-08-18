import { describe, expect, it } from "vitest";

import { createIncidentReadAdapter } from "../src/api-adapter.ts";
import { WEB_SECURITY_HEADERS } from "../vite.config.ts";

describe("browser API authority boundary", () => {
  it("does not expose simulator execution admission", () => {
    const adapter = createIncidentReadAdapter({ baseUrl: "https://web.test" });

    expect(adapter).not.toHaveProperty("admitSimulatorAction");
    expect(Object.keys(adapter)).not.toContain("simulatorActions");
  });

  it("hardens runnable web responses without enabling inline script", () => {
    expect(WEB_SECURITY_HEADERS["Cache-Control"]).toBe("no-store");
    expect(WEB_SECURITY_HEADERS["Content-Security-Policy"]).toContain("script-src 'self'");
    expect(WEB_SECURITY_HEADERS["Content-Security-Policy"]).not.toContain(
      "script-src 'unsafe-inline'",
    );
    expect(WEB_SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
    expect(WEB_SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
  });
});
