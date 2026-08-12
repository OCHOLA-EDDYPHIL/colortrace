import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const trackedOutput = resolve(packageRoot, "src/generated");

const snapshot = async (root) => {
  const files = new Map();

  const visit = async (directory) => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));

    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isFile()) {
        files.set(relative(root, path), await readFile(path));
      } else {
        throw new Error(`Generated output contains an unsupported entry: ${path}`);
      }
    }
  };

  await visit(root);
  return files;
};

const compare = (tracked, candidate) => {
  const differences = [];
  const paths = [...new Set([...tracked.keys(), ...candidate.keys()])].sort((left, right) =>
    left.localeCompare(right, "en"),
  );

  for (const path of paths) {
    const trackedContents = tracked.get(path);
    const candidateContents = candidate.get(path);

    if (trackedContents === undefined) {
      differences.push(`missing tracked file: ${path}`);
    } else if (candidateContents === undefined) {
      differences.push(`unexpected tracked file: ${path}`);
    } else if (!trackedContents.equals(candidateContents)) {
      differences.push(`changed file: ${path}`);
    }
  }

  return differences;
};

const temporaryRoot = await mkdtemp(join(tmpdir(), "colortrace-api-client-"));
const candidateOutput = join(temporaryRoot, "generated");

try {
  const executable = process.platform === "win32" ? "openapi-ts.cmd" : "openapi-ts";
  const generation = spawnSync(
    executable,
    [
      "--file",
      resolve(packageRoot, "openapi-ts.config.ts"),
      "--output",
      candidateOutput,
      "--silent",
    ],
    {
      cwd: packageRoot,
      stdio: "inherit",
    },
  );

  if (generation.error) {
    throw generation.error;
  }
  if (generation.status !== 0) {
    throw new Error(`Client generation exited with status ${generation.status ?? "unknown"}`);
  }

  const biomeExecutable = process.platform === "win32" ? "biome.cmd" : "biome";
  const formatting = spawnSync(biomeExecutable, ["format", "--write", candidateOutput], {
    cwd: packageRoot,
    stdio: "inherit",
  });

  if (formatting.error) {
    throw formatting.error;
  }
  if (formatting.status !== 0) {
    throw new Error(
      `Generated client formatting exited with status ${formatting.status ?? "unknown"}`,
    );
  }

  const differences = compare(await snapshot(trackedOutput), await snapshot(candidateOutput));
  if (differences.length > 0) {
    console.error("Generated API client is out of date:");
    for (const difference of differences) {
      console.error(`- ${difference}`);
    }
    process.exitCode = 1;
  }
} finally {
  if (basename(temporaryRoot).startsWith("colortrace-api-client-")) {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
