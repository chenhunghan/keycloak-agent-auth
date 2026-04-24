/**
 * Admin-plane helpers. Uses Keycloak's OIDC password grant to get an admin
 * token, then calls the extension's admin API to register a capability and
 * approve pending grants.
 *
 * These operations are NOT part of the Agent Auth Protocol flow itself —
 * they're the deployment-time setup a service operator does once (or when
 * capabilities change). Included here so the demo can be run from scratch.
 */

export async function getAdminToken(
  kcBaseUrl: string,
  realm: string,
  username: string,
  password: string,
): Promise<string> {
  const resp = await fetch(
    `${kcBaseUrl}/realms/${realm}/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username,
        password,
      }).toString(),
    },
  );
  if (!resp.ok) {
    throw new Error(
      `admin token failed: ${resp.status} ${await resp.text()}`,
    );
  }
  const body = (await resp.json()) as { access_token: string };
  return body.access_token;
}

export interface CapabilityDefinition {
  name: string;
  description: string;
  visibility: "authenticated" | "public";
  requires_approval: boolean;
  location: string;
  input?: unknown;
  output?: unknown;
}

export async function registerCapability(
  kcBaseUrl: string,
  realm: string,
  adminToken: string,
  capability: CapabilityDefinition,
): Promise<"created" | "already_exists"> {
  const url = `${kcBaseUrl}/admin/realms/${realm}/agent-auth/capabilities`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify(capability),
  });
  if (resp.status === 409) return "already_exists";
  if (!resp.ok) {
    throw new Error(
      `register capability failed: ${resp.status} ${await resp.text()}`,
    );
  }
  return "created";
}

/**
 * Approves a pending capability grant on an agent. This is the admin-mediated
 * approval path the extension uses when `approval_methods=["admin"]` or when
 * the admin shortcut is preferred over device-flow. AAP §2.9 / §5.3.
 */
export async function approveCapability(
  kcBaseUrl: string,
  realm: string,
  adminToken: string,
  agentId: string,
  capability: string,
): Promise<void> {
  const url = `${kcBaseUrl}/admin/realms/${realm}/agent-auth/agents/${agentId}/capabilities/${capability}/approve`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${adminToken}` },
  });
  if (!resp.ok) {
    throw new Error(
      `approve failed: ${resp.status} ${await resp.text()}`,
    );
  }
}
