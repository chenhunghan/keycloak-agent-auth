import { createServer, type IncomingMessage, type Server } from "node:http";

export interface CapabilityHandler {
  (args: Record<string, unknown>): Record<string, unknown>;
}

/**
 * The **Resource Server** — where capability business logic actually runs.
 *
 * In gateway mode (what this demo uses), Keycloak validates the agent+jwt,
 * runs constraint checks, and then proxies the request to this server. The
 * server simply executes the business logic and returns a JSON body
 * wrapped in a `data` field (per the spec's §5.11 sync response shape).
 *
 * A production resource server running in **direct mode** would also
 * validate the agent JWT itself — either by calling Keycloak's
 * /agent/introspect or by checking signature + aud locally against the
 * agent's registered public key. For this mini demo we rely on gateway
 * mode so the resource server has nothing to auth.
 */
export class ResourceServer {
  private constructor(
    private readonly server: Server,
    readonly port: number,
  ) {}

  /** Start on a random free port (useful for tests). */
  static async start(
    handlers: Record<string, CapabilityHandler>,
  ): Promise<ResourceServer> {
    return ResourceServer.startOn(0, handlers);
  }

  /** Start on a specific port (used by the dockerized demo). */
  static async startOn(
    port: number,
    handlers: Record<string, CapabilityHandler>,
  ): Promise<ResourceServer> {
    return await new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        handle(req, res, handlers).catch((err) => {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: String(err) }));
        });
      });
      server.on("error", reject);
      server.listen(port, "0.0.0.0", () => {
        const address = server.address();
        if (address && typeof address === "object") {
          console.log(`[resource-server] listening on :${address.port}`);
          resolve(new ResourceServer(server, address.port));
        } else {
          reject(new Error("failed to bind"));
        }
      });
    });
  }

  /**
   * Capability URL reachable by Keycloak (and the rest of the compose
   * network) at the configured service name. When the demo registers a
   * capability with this URL as its `location`, KC's gateway proxy hits it.
   */
  urlFor(path: string, serviceHost = "resource-server"): string {
    return `http://${serviceHost}:${this.port}${path}`;
  }

  close(): void {
    this.server.close();
  }
}

async function handle(
  req: IncomingMessage,
  res: import("node:http").ServerResponse,
  handlers: Record<string, CapabilityHandler>,
): Promise<void> {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end();
    return;
  }
  const path = req.url ?? "";
  const handler = handlers[path];
  if (!handler) {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found", path }));
    return;
  }
  const bodyStr = await readBody(req);
  const parsed = bodyStr ? (JSON.parse(bodyStr) as Record<string, unknown>) : {};
  const args = (parsed.arguments as Record<string, unknown>) ?? {};
  console.log(`[resource-server] ${path}  args=${JSON.stringify(args)}`);
  const data = handler(args);
  res.statusCode = 200;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ data }));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}
