import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createIncidentReadAdapter } from "./api-adapter.ts";
import { createDemoAdapter } from "./demo-api.ts";
import { captureHostOidcTokenProvider } from "./host-auth.ts";
import { IncidentWorkspaceApp } from "./incident-workspace-app.tsx";
import { ShotSafeColorRecoveryApp } from "./shot-safe-color-recovery-app.tsx";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Missing application root");
}

const showIncidentWorkspace =
  window.location.pathname === "/workspace" || window.location.pathname.startsWith("/workspace/");
const application = showIncidentWorkspace ? (
  (() => {
    const tokenProvider = captureHostOidcTokenProvider(window);
    const adapter = createIncidentReadAdapter({
      baseUrl: window.location.origin,
      ...(tokenProvider === undefined ? {} : { tokenProvider }),
    });
    return <IncidentWorkspaceApp adapter={adapter} />;
  })()
) : (
  <ShotSafeColorRecoveryApp adapter={createDemoAdapter({ baseUrl: window.location.origin })} />
);

createRoot(root).render(<StrictMode>{application}</StrictMode>);
