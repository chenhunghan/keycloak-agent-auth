import {
  approveCapability,
  getAdminToken,
  registerCapability,
} from "./admin.js";
import { Agent } from "./agent.js";
import { Client } from "./client.js";

const KC_BASE = process.env.KC_BASE ?? "http://localhost:28080";
const REALM = process.env.KC_REALM ?? "master";
const ADMIN_USER = process.env.KC_ADMIN_USER ?? "admin";
const ADMIN_PASS = process.env.KC_ADMIN_PASS ?? "admin";
/** URL Keycloak (inside docker) uses to reach the resource server. */
const RS_LOCATION =
  process.env.RS_LOCATION ?? "http://resource-server:3000/exec/greet";

const issuer = `${KC_BASE}/realms/${REALM}/agent-auth`;

function uniqueSuffix(): string {
  return Math.random().toString(36).slice(2, 10);
}

/**
 * Mirrors AgentAuthFullJourneyE2E.autonomousJourneyActiveImmediately:
 *
 *   admin registers auto-approved capability → agent registers autonomous
 *   (active immediately) → execute → introspect active → revoke →
 *   post-revoke execute rejected → post-revoke introspect inactive.
 */
async function autonomousJourney(adminToken: string): Promise<void> {
  const capName = `greet_autonomous_${uniqueSuffix()}`;
  console.log(`\n=== autonomous journey (capability: ${capName}) ===`);

  // 1. admin registers an auto-approved capability
  console.log("1. admin registers capability (requires_approval=false)");
  await registerCapability(KC_BASE, REALM, adminToken, {
    name: capName,
    description: "Demo greet, auto-approved",
    visibility: "authenticated",
    requires_approval: false,
    location: RS_LOCATION,
    input: { type: "object", properties: { name: { type: "string" } } },
    output: { type: "object" },
  });

  // 2. agent registers autonomous — active immediately
  console.log("2. agent registers (mode=autonomous)");
  const client = await Client.create(issuer);
  const reg = await client.registerAgent({
    name: "demo-autonomous-agent",
    host_name: "demo-host",
    mode: "autonomous",
    capabilities: [capName],
    reason: "Demo autonomous journey",
  });
  console.log(`   agent_id=${reg.agent_id}  status=${reg.status}`);
  if (reg.status !== "active") {
    throw new Error(`expected active, got ${reg.status}`);
  }

  // 3. execute hits the backend
  console.log("3. execute via gateway");
  const agent = new Agent(client, reg.agent_id);
  const result = (await agent.invokeTool(capName, { name: "autonomous" })) as {
    data: { greeting: string };
  };
  console.log(`   backend returned: "${result.data.greeting}"`);

  // 4. introspect reports active
  console.log("4. introspect");
  const intro1 = await client.introspectAgent();
  console.log(`   active=${intro1.active}`);
  if (intro1.active !== true) throw new Error("expected active=true");

  // 5. revoke
  console.log("5. revoke");
  await client.revokeAgent();

  // 6. post-revoke execute is rejected
  console.log("6. post-revoke execute (expected: rejected)");
  const postExec = await client.tryExecute(capName, { name: "autonomous" });
  console.log(`   status=${postExec.status}`);
  if (postExec.status === 200) {
    throw new Error("expected execute to fail after revoke");
  }

  // 7. post-revoke introspect reports inactive
  console.log("7. post-revoke introspect (expected: active=false)");
  const intro2 = await client.introspectAgent();
  console.log(`   active=${intro2.active}`);
  if (intro2.active !== false) throw new Error("expected active=false");

  console.log("autonomous journey: OK");
}

/**
 * Mirrors AgentAuthFullJourneyE2E.delegatedJourneyPendingUntilApproved:
 *
 *   admin registers approval-required capability → agent registers delegated
 *   (pending) → admin approves grant → status=active → execute → introspect
 *   active → revoke → post-revoke execute rejected → post-revoke introspect
 *   inactive.
 */
async function delegatedJourney(adminToken: string): Promise<void> {
  const capName = `greet_delegated_${uniqueSuffix()}`;
  console.log(`\n=== delegated journey (capability: ${capName}) ===`);

  // 1. admin registers an approval-required capability
  console.log("1. admin registers capability (requires_approval=true)");
  await registerCapability(KC_BASE, REALM, adminToken, {
    name: capName,
    description: "Demo greet, approval required",
    visibility: "authenticated",
    requires_approval: true,
    location: RS_LOCATION,
    input: { type: "object", properties: { name: { type: "string" } } },
    output: { type: "object" },
  });

  // 2. agent registers delegated — lands in pending
  console.log("2. agent registers (mode=delegated) → expect pending");
  const client = await Client.create(issuer);
  const reg = await client.registerAgent({
    name: "demo-delegated-agent",
    host_name: "demo-host",
    mode: "delegated",
    capabilities: [capName],
    reason: "Demo delegated journey",
  });
  console.log(`   agent_id=${reg.agent_id}  status=${reg.status}`);
  if (reg.status !== "pending") {
    throw new Error(`expected pending, got ${reg.status}`);
  }

  // 3. admin approves the grant — agent flips to active
  console.log("3. admin approves grant");
  await approveCapability(KC_BASE, REALM, adminToken, reg.agent_id, capName);
  const postApprove = await client.getAgentStatus();
  console.log(`   agent status=${postApprove}`);
  if (postApprove !== "active") {
    throw new Error(`expected active after approve, got ${postApprove}`);
  }

  // 4. execute hits the backend
  console.log("4. execute via gateway");
  const agent = new Agent(client, reg.agent_id);
  const result = (await agent.invokeTool(capName, { name: "delegated" })) as {
    data: { greeting: string };
  };
  console.log(`   backend returned: "${result.data.greeting}"`);

  // 5. introspect reports active
  console.log("5. introspect");
  const intro1 = await client.introspectAgent();
  console.log(`   active=${intro1.active}`);
  if (intro1.active !== true) throw new Error("expected active=true");

  // 6. revoke
  console.log("6. revoke");
  await client.revokeAgent();

  // 7. post-revoke execute is rejected
  console.log("7. post-revoke execute (expected: rejected)");
  const postExec = await client.tryExecute(capName, { name: "delegated" });
  console.log(`   status=${postExec.status}`);
  if (postExec.status === 200) {
    throw new Error("expected execute to fail after revoke");
  }

  // 8. post-revoke introspect reports inactive
  console.log("8. post-revoke introspect (expected: active=false)");
  const intro2 = await client.introspectAgent();
  console.log(`   active=${intro2.active}`);
  if (intro2.active !== false) throw new Error("expected active=false");

  console.log("delegated journey: OK");
}

async function main(): Promise<void> {
  console.log(`[demo] Keycloak: ${issuer}`);
  console.log(`[demo] Resource Server (as seen by KC): ${RS_LOCATION}`);

  const adminToken = await getAdminToken(KC_BASE, REALM, ADMIN_USER, ADMIN_PASS);

  await autonomousJourney(adminToken);
  await delegatedJourney(adminToken);

  console.log("\nAll journeys: OK");
}

main().catch((err) => {
  console.error("\n[demo] FAILED:", err);
  process.exit(1);
});
