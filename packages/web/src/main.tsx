import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createDemoAdapter } from "./demo-api.ts";
import { ShotSafeColorRecoveryApp } from "./shot-safe-color-recovery-app.tsx";
import "./styles.css";

const legacyWorkspace =
  window.location.pathname === "/workspace" || window.location.pathname.startsWith("/workspace/");

if (legacyWorkspace) {
  window.location.replace("/");
} else {
  const root = document.getElementById("root");
  if (root === null) throw new Error("Missing application root");
  createRoot(root).render(
    <StrictMode>
      <ShotSafeColorRecoveryApp adapter={createDemoAdapter({ baseUrl: window.location.origin })} />
    </StrictMode>,
  );
}
