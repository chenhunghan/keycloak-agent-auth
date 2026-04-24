import { ResourceServer } from "./resource-server.js";

// Entrypoint when the resource server runs as a standalone service
// (inside docker compose, alongside Keycloak).
const PORT = Number(process.env.PORT ?? 3000);

async function main(): Promise<void> {
  await ResourceServer.startOn(PORT, {
    "/exec/greet": (args) => {
      const name = typeof args.name === "string" ? args.name : "world";
      return { greeting: `Hello, ${name}!` };
    },
  });
  console.log(`[rs-standalone] ready`);
  // Keep the process alive.
  await new Promise(() => {});
}

main().catch((err) => {
  console.error("[rs-standalone] fatal:", err);
  process.exit(1);
});
