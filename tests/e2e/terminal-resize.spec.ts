import { expect, test, type APIRequestContext } from "@playwright/test";
import { execFileSync } from "node:child_process";
import WebSocket from "ws";

function sessionName(engine: string, width: number): string {
  const nonce = Math.random().toString(36).slice(2, 7);
  return `e2e-terminal-resize-${engine}-${width}-${Date.now().toString(36)}-${nonce}`;
}

async function deleteSession(request: APIRequestContext, name: string): Promise<void> {
  await request.delete(`/api/sessions/${encodeURIComponent(name)}`).catch(() => undefined);
}

interface TerminalConnection {
  initialCols: number | null;
  initialRows: number | null;
  resizeFrames: Array<{ cols: number; rows: number }>;
}

test("server attaches tmux at the dimensions supplied in the terminal URL", async ({
  request,
  baseURL,
}) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");

  const name = sessionName("server", 123);
  const created = await request.post("/api/sessions", {
    data: { name, kind: "bash", cwd: "." },
  });
  expect(created.ok(), await created.text()).toBe(true);

  const socket = new WebSocket(
    `${baseURL.replace(/^http/, "ws")}/ws/terminal/${encodeURIComponent(name)}?cols=123&rows=37`
  );

  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("open", resolve);
      socket.once("error", reject);
    });

    await expect
      .poll(() => {
        try {
          return execFileSync(
            "tmux",
            ["list-clients", "-t", `=${name}`, "-F", "#{client_width}x#{client_height}"],
            { encoding: "utf8" }
          )
            .trim()
            .split("\n");
        } catch {
          return [];
        }
      })
      .toContain("123x37");
  } finally {
    socket.terminate();
    await deleteSession(request, name);
  }
});

const cases = (["xterm", "wterm"] as const).flatMap((engine) =>
  [375, 768, 1280].map((width) => ({ engine, width }))
);

for (const { engine, width } of cases) {
  test(`${engine} attaches once at its fitted dimensions at ${width}px`, async ({
    page,
    request,
  }) => {
    const name = sessionName(engine, width);
    const created = await request.post("/api/sessions", {
      data: { name, kind: "bash", cwd: "." },
    });
    expect(created.ok(), await created.text()).toBe(true);

    const terminalConnections: TerminalConnection[] = [];
    page.on("websocket", (socket) => {
      if (!socket.url().includes("/ws/terminal/")) return;

      const url = new URL(socket.url());
      const connection: TerminalConnection = {
        initialCols: url.searchParams.has("cols") ? Number(url.searchParams.get("cols")) : null,
        initialRows: url.searchParams.has("rows") ? Number(url.searchParams.get("rows")) : null,
        resizeFrames: [],
      };
      terminalConnections.push(connection);

      socket.on("framesent", (event) => {
        const payload =
          typeof event.payload === "string" ? event.payload : event.payload.toString();
        try {
          const message = JSON.parse(payload) as { type?: string; cols?: number; rows?: number };
          if (message.type === "resize" && message.cols && message.rows) {
            connection.resizeFrames.push({ cols: message.cols, rows: message.rows });
          }
        } catch {
          // Terminal input frames are not JSON resize messages.
        }
      });
    });

    try {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript((selectedEngine) => {
        window.localStorage.setItem("terminalx.engine", selectedEngine);
      }, engine);
      await page.goto(`/workspace/${encodeURIComponent(name)}`);
      await expect.poll(() => terminalConnections.length).toBeGreaterThan(0);
      await expect.poll(() => terminalConnections[0]?.resizeFrames.length ?? 0).toBeGreaterThan(0);

      await page.waitForTimeout(1_500);
      expect(terminalConnections, "stale terminal sockets must not reconnect").toHaveLength(1);

      const connection = terminalConnections[0];
      if (!connection) throw new Error("terminal WebSocket was not created");
      const fitted = connection.resizeFrames.at(-1);
      if (!fitted) throw new Error("terminal did not send its fitted dimensions");

      expect(
        connection.initialCols,
        "terminal URL must include its fitted column count"
      ).not.toBeNull();
      expect(
        connection.initialRows,
        "terminal URL must include its fitted row count"
      ).not.toBeNull();
      expect(
        Math.abs((connection.initialCols ?? 0) - fitted.cols),
        `terminal attached at ${connection.initialCols} columns before fitting to ${fitted.cols}`
      ).toBeLessThanOrEqual(1);
      expect(
        Math.abs((connection.initialRows ?? 0) - fitted.rows),
        `terminal attached at ${connection.initialRows} rows before fitting to ${fitted.rows}`
      ).toBeLessThanOrEqual(1);
    } finally {
      await deleteSession(request, name);
    }
  });
}
