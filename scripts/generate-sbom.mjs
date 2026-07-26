#!/usr/bin/env node
// Generate SPDX 2.3 JSON SBOMs for the TerminalX app and its sibling packages.
//
// House convention (see .github/workflows/daytona-sdk-artifact.yml) is SPDX 2.3
// JSON + sha256 checksums, not CycloneDX/cosign. This generator is self-contained
// (it walks package-lock.json + each package.json; no syft/cyclonedx/network) so
// it runs in CI and locally. Each SBOM lists resolved dependency packages with
// name, version, and download location, plus a documentDescribes root.
//
// Usage:
//   node scripts/generate-sbom.mjs <output-dir>
// Emits (fail-if-exists): <dir>/sbom-app.spdx.json, sbom-daytona-supervisor.spdx.json,
//   sbom-secret-broker.spdx.json, and checksums.sha256 over all three.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function spdxId(prefix, name, version) {
  const safe = `${name}@${version}`.replace(/[^a-zA-Z0-9.-]/g, "-");
  return `SPDXRef-${prefix}-${safe}`;
}

function nowIso() {
  // Deterministic-friendly: allow SOURCE_DATE_EPOCH override for reproducibility.
  const epoch = process.env.SOURCE_DATE_EPOCH;
  const date = epoch ? new Date(Number(epoch) * 1000) : new Date();
  return `${date.toISOString().replace(/\.\d{3}Z$/, "Z")}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * Build the resolved dependency set for a package from the root package-lock.
 * package-lock v3 keys every installed tree node under "packages" by its path.
 */
function resolvedDependencies(lock, scopePrefix) {
  const packages = lock.packages ?? {};
  const results = [];
  for (const [path, node] of Object.entries(packages)) {
    if (path === "") continue; // the root project itself
    if (!path.startsWith("node_modules/")) continue;
    // scopePrefix "" == the app (top-level node_modules). Sibling packages
    // resolve their deps from the same hoisted tree in this monorepo.
    if (scopePrefix && !path.startsWith(scopePrefix)) continue;
    const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
    if (!node.version) continue;
    results.push({
      name,
      version: node.version,
      resolved: node.resolved ?? "NOASSERTION",
      integrity: node.integrity ?? null,
      dev: node.dev === true,
    });
  }
  // De-duplicate by name@version (hoisted trees can repeat).
  const seen = new Set();
  return results.filter((d) => {
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildSpdx({ documentName, rootName, rootVersion, deps }) {
  const namespace = `https://terminalx.dev/spdx/${documentName}-${rootVersion}-${createHash(
    "sha256"
  )
    .update(`${rootName}@${rootVersion}`)
    .digest("hex")
    .slice(0, 16)}`;
  const rootId = spdxId("Package", rootName, rootVersion);
  const packages = [
    {
      SPDXID: rootId,
      name: rootName,
      versionInfo: rootVersion,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      supplier: "Organization: TerminalX Contributors",
    },
  ];
  const relationships = [
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: rootId,
    },
  ];
  for (const dep of deps) {
    const id = spdxId("Package", dep.name, dep.version);
    const externalRefs = [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:npm/${dep.name.replace("@", "%40")}@${dep.version}`,
      },
    ];
    const pkg = {
      SPDXID: id,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: dep.resolved,
      filesAnalyzed: false,
      externalRefs,
      primaryPackagePurpose: dep.dev ? "OTHER" : "LIBRARY",
    };
    if (dep.integrity) {
      const [algo, b64] = dep.integrity.split("-");
      if (algo && b64 && algo.startsWith("sha")) {
        pkg.checksums = [
          {
            algorithm: algo.toUpperCase().replace("SHA", "SHA"),
            checksumValue: Buffer.from(b64, "base64").toString("hex"),
          },
        ];
      }
    }
    packages.push(pkg);
    relationships.push({
      spdxElementId: rootId,
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: id,
    });
  }
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: documentName,
    documentNamespace: namespace,
    creationInfo: {
      created: nowIso(),
      creators: ["Tool: terminalx-generate-sbom", "Organization: TerminalX Contributors"],
    },
    packages,
    relationships,
  };
}

function writeArtifact(outDir, filename, doc) {
  const path = join(outDir, filename);
  if (existsSync(path)) {
    throw new Error(`refusing to overwrite existing artifact: ${path}`);
  }
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  writeFileSync(path, json, { encoding: "utf8", flag: "wx", mode: 0o644 });
  return { path, sha256: createHash("sha256").update(json).digest("hex") };
}

function main() {
  const outDir = process.argv[2];
  if (!outDir) {
    process.stderr.write("usage: node scripts/generate-sbom.mjs <output-dir>\n");
    process.exit(64);
  }
  mkdirSync(outDir, { recursive: true });

  const lock = readJson(join(ROOT, "package-lock.json"));
  const appPkg = readJson(join(ROOT, "package.json"));
  const deps = resolvedDependencies(lock, "");

  const targets = [
    {
      filename: "sbom-app.spdx.json",
      documentName: "terminalx-app",
      rootName: appPkg.name,
      rootVersion: appPkg.version,
      deps,
    },
  ];
  for (const rel of ["packages/daytona-supervisor", "packages/secret-broker"]) {
    const pkgPath = join(ROOT, rel, "package.json");
    if (!existsSync(pkgPath)) continue;
    const pkg = readJson(pkgPath);
    // Sibling packages resolve their runtime deps from the hoisted monorepo tree.
    const scopedDeps = deps.filter((d) => Object.keys(pkg.dependencies ?? {}).includes(d.name));
    targets.push({
      filename: `sbom-${pkg.name.replace(/^@[^/]+\//, "").replace(/[^a-z0-9-]/gi, "-")}.spdx.json`,
      documentName: pkg.name,
      rootName: pkg.name,
      rootVersion: pkg.version,
      deps: scopedDeps,
    });
  }

  const checksums = [];
  for (const t of targets) {
    const doc = buildSpdx(t);
    const { path, sha256 } = writeArtifact(outDir, t.filename, doc);
    checksums.push(`${sha256}  ${t.filename}`);
    process.stdout.write(`wrote ${path} (${doc.packages.length - 1} deps)\n`);
  }
  const checksumPath = join(outDir, "checksums.sha256");
  if (existsSync(checksumPath)) throw new Error(`refusing to overwrite ${checksumPath}`);
  writeFileSync(checksumPath, `${checksums.join("\n")}\n`, { flag: "wx", mode: 0o644 });
  process.stdout.write(`wrote ${checksumPath}\n`);
}

main();
