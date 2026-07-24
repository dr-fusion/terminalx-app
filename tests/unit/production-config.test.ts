import * as fs from "fs";
import * as path from "path";
import { describe, expect, it } from "vitest";

function projectFile(relativePath: string): string {
  return fs.readFileSync(path.join(process.cwd(), relativePath), "utf8");
}

describe("production configuration", () => {
  it("pins patched framework and image-processing dependencies", () => {
    const pkg = JSON.parse(projectFile("package.json")) as {
      dependencies: Record<string, string>;
      overrides: Record<string, string>;
    };

    expect(pkg.dependencies.next).toBe("16.2.11");
    expect(pkg.dependencies.tsx).toBe("4.23.1");
    expect(pkg.overrides.sharp).toBe("0.35.3");
  });

  it("pins every CI action to an immutable commit", () => {
    const workflow = projectFile(".github/workflows/ci.yml");
    const actionReferences = [...workflow.matchAll(/^\s*- uses:\s+([^\s#]+)/gm)].map(
      (match) => match[1]
    );

    expect(actionReferences.length).toBeGreaterThan(0);
    expect(actionReferences.every((reference) => /@[0-9a-f]{40}$/.test(reference!))).toBe(true);
    expect(workflow).toContain("npm audit --omit=dev --audit-level=high");
    expect(workflow).toContain("sbom: true");
    expect(workflow).toContain("provenance: mode=max");
  });

  it("uses an immutable LTS base and a non-root runtime image", () => {
    const dockerfile = projectFile("Dockerfile");

    expect(dockerfile).toMatch(/node:24-bookworm-slim@sha256:[0-9a-f]{64}/);
    expect(dockerfile).toContain("FROM ${NODE_IMAGE} AS build");
    expect(dockerfile).toContain("FROM ${NODE_IMAGE} AS runtime");
    expect(dockerfile).toContain("npm prune --omit=dev");
    expect(dockerfile).toContain("USER terminus");
    expect(dockerfile).not.toContain("ENV TERMINALX_AUTH_MODE");
  });

  it("uses the supported Next.js proxy convention for the auth boundary", () => {
    expect(fs.existsSync(path.join(process.cwd(), "src", "middleware.ts"))).toBe(false);
    expect(projectFile("src/proxy.ts")).toContain("export async function proxy");
  });

  it("keeps authentication configuration runtime-only", () => {
    const nextConfig = projectFile("next.config.ts");

    expect(nextConfig).not.toMatch(/env\s*:\s*\{[\s\S]*TERMINALX_AUTH_MODE/);
  });

  it("does not mount the host home and drops container privileges", () => {
    const compose = projectFile("docker-compose.yml");

    expect(compose).not.toContain("${HOME");
    expect(compose).not.toMatch(/:\/root(?:\s|$)/m);
    expect(compose).toContain("terminalx-workspaces:/workspace");
    expect(compose).toContain("read_only: true");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toMatch(/cap_drop:\s*\n\s*- ALL/);
  });

  it("never prints generated credentials to container logs", () => {
    const entrypoint = projectFile("docker-entrypoint.sh");

    expect(entrypoint).toContain("TERMINALX_ADMIN_PASSWORD_FILE");
    expect(entrypoint).toContain("TERMINALX_JWT_SECRET_FILE");
    expect(entrypoint).not.toMatch(/echo[^\n]*\$TERMINALX_ADMIN_PASSWORD/);
  });
});
