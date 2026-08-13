import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createIncidentReadAdapter } from "./api-adapter.ts";
import { captureHostOidcTokenProvider } from "./host-auth.ts";
import { IncidentWorkspaceApp } from "./incident-workspace-app.tsx";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Missing application root");
}

const tokenProvider = captureHostOidcTokenProvider(window);
const adapter = createIncidentReadAdapter({
  baseUrl: window.location.origin,
  ...(tokenProvider === undefined ? {} : { tokenProvider }),
});

createRoot(root).render(
  <StrictMode>
    <IncidentWorkspaceApp adapter={adapter} />
  </StrictMode>,
);
