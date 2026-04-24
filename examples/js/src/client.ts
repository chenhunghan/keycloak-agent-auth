import {
  calculateJwkThumbprint,
  exportJWK,
  type JWK,
  SignJWT,
} from "jose";
import {
  generateKeyPair as nodeGenerateKeyPair,
  KeyObject,
  randomUUID,
} from "node:crypto";
import { promisify } from "node:util";

const generateKeyPair = promisify(nodeGenerateKeyPair);

export type Ed25519KeyPair = { publicKey: KeyObject; privateKey: KeyObject };

async function generateEd25519(): Promise<Ed25519KeyPair> {
  return (await generateKeyPair("ed25519")) as Ed25519KeyPair;
}

async function publicJwk(key: KeyObject): Promise<JWK> {
  return await exportJWK(key);
}

async function thumbprint(key: KeyObject): Promise<string> {
  return await calculateJwkThumbprint(await publicJwk(key), "sha256");
}

export interface AgentRegistration {
  name: string;
  host_name?: string;
  mode: "delegated" | "autonomous";
  capabilities: (string | { name: string; constraints?: unknown })[];
  reason?: string;
}

export interface AgentRegistrationResponse {
  agent_id: string;
  status: "pending" | "active" | "rejected";
  approval?: Record<string, unknown>;
  agent_capability_grants?: Array<{
    capability: string;
    status: string;
    [k: string]: unknown;
  }>;
}

export interface IntrospectResponse {
  active: boolean;
  agent_id?: string;
  host_id?: string;
  mode?: string;
  expires_at?: string;
  agent_capability_grants?: Array<{ capability: string; status: string }>;
}

export interface ExecuteAttempt {
  status: number;
  body: unknown;
}

/**
 * The **Client** — a broker process.
 *
 * Per AAP §1.5/§1.6, the Client is "the process that holds a host identity
 * and exposes protocol tools to AI systems (MCP server, CLI, SDK). It
 * manages host and agent keys, talks to servers, and signs JWTs."
 *
 * In this demo the Client:
 *   - generates an in-memory Ed25519 keypair (the Host identity)
 *   - generates a second Ed25519 keypair per Agent registered under it
 *   - mints host+jwt (§4.2) for host-scoped ops (register, revoke, introspect)
 *   - mints agent+jwt (§4.3) for /capability/execute (gateway mode)
 *
 * A production Client would persist the host key (OS keychain, secrets
 * manager, disk with correct permissions) so the Host identity survives
 * restarts.
 */
export class Client {
  private readonly hostKey: Ed25519KeyPair;
  private agentKey: Ed25519KeyPair | null = null;
  private agentId: string | null = null;

  private constructor(
    private readonly issuerUrl: string,
    hostKey: Ed25519KeyPair,
  ) {
    this.hostKey = hostKey;
  }

  static async create(issuerUrl: string): Promise<Client> {
    const hostKey = await generateEd25519();
    return new Client(issuerUrl, hostKey);
  }

  /** Register a new Agent under this Host. Returns the full response. */
  async registerAgent(req: AgentRegistration): Promise<AgentRegistrationResponse> {
    this.agentKey = await generateEd25519();
    const hostJwt = await this.mintHostJwtForRegistration();

    const resp = await fetch(`${this.issuerUrl}/agent/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${hostJwt}`,
      },
      body: JSON.stringify(req),
    });
    if (!resp.ok) {
      throw new Error(
        `POST /agent/register failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const body = (await resp.json()) as AgentRegistrationResponse;
    this.agentId = body.agent_id;
    return body;
  }

  /** GET /agent/status?agent_id=... — returns the current status. */
  async getAgentStatus(): Promise<string> {
    if (!this.agentId) throw new Error("no agent registered");
    const hostJwt = await this.mintHostJwtForOp();
    const resp = await fetch(
      `${this.issuerUrl}/agent/status?agent_id=${this.agentId}`,
      {
        headers: { authorization: `Bearer ${hostJwt}` },
      },
    );
    if (!resp.ok) {
      throw new Error(
        `GET /agent/status failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const body = (await resp.json()) as { status: string };
    return body.status;
  }

  /**
   * Execute a capability in gateway mode.
   * Throws on non-2xx (for happy-path callers). Use `tryExecute` to inspect
   * a possibly-failing response (e.g. post-revocation).
   */
  async executeViaGateway(capability: string, args: unknown): Promise<unknown> {
    const attempt = await this.tryExecute(capability, args);
    if (attempt.status < 200 || attempt.status >= 300) {
      throw new Error(
        `POST /capability/execute failed: ${attempt.status} ${JSON.stringify(attempt.body)}`,
      );
    }
    return attempt.body;
  }

  /** Like `executeViaGateway` but surfaces the status code instead of throwing. */
  async tryExecute(capability: string, args: unknown): Promise<ExecuteAttempt> {
    if (!this.agentKey || !this.agentId) throw new Error("no agent registered");
    const executeUrl = `${this.issuerUrl}/capability/execute`;
    const agentJwt = await this.mintAgentJwt(executeUrl);
    const resp = await fetch(executeUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${agentJwt}`,
      },
      body: JSON.stringify({ capability, arguments: args }),
    });
    const text = await resp.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: resp.status, body };
  }

  /**
   * POST /agent/introspect — asks Keycloak to validate the current agent's
   * JWT. Returns `{ active: true, ... }` or `{ active: false }`.
   */
  async introspectAgent(): Promise<IntrospectResponse> {
    if (!this.agentKey || !this.agentId) throw new Error("no agent registered");
    const agentJwt = await this.mintAgentJwt(this.issuerUrl);
    const hostJwt = await this.mintHostJwtForOp();
    const resp = await fetch(`${this.issuerUrl}/agent/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${hostJwt}`,
      },
      body: JSON.stringify({ token: agentJwt }),
    });
    if (!resp.ok) {
      throw new Error(
        `POST /agent/introspect failed: ${resp.status} ${await resp.text()}`,
      );
    }
    return (await resp.json()) as IntrospectResponse;
  }

  /** POST /agent/revoke — permanently terminates the current agent. */
  async revokeAgent(): Promise<void> {
    if (!this.agentId) throw new Error("no agent registered");
    const hostJwt = await this.mintHostJwtForOp();
    const resp = await fetch(`${this.issuerUrl}/agent/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${hostJwt}`,
      },
      body: JSON.stringify({ agent_id: this.agentId }),
    });
    if (!resp.ok) {
      throw new Error(
        `POST /agent/revoke failed: ${resp.status} ${await resp.text()}`,
      );
    }
  }

  /** Current agent_id (null until registerAgent is called). */
  get currentAgentId(): string | null {
    return this.agentId;
  }

  // ---------- JWT minting ----------

  /** host+jwt for POST /agent/register — includes agent_public_key. (§4.2) */
  private async mintHostJwtForRegistration(): Promise<string> {
    if (!this.agentKey) throw new Error("agent key not prepared");
    const hostPub = await publicJwk(this.hostKey.publicKey);
    const agentPub = await publicJwk(this.agentKey.publicKey);
    const iss = await thumbprint(this.hostKey.publicKey);

    return await new SignJWT({
      host_public_key: hostPub,
      agent_public_key: agentPub,
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
      .setIssuer(iss)
      .setAudience(this.issuerUrl)
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(`h-${randomUUID()}`)
      .sign(this.hostKey.privateKey);
  }

  /** host+jwt for non-registration host ops (status, revoke, introspect). (§4.2) */
  private async mintHostJwtForOp(): Promise<string> {
    const hostPub = await publicJwk(this.hostKey.publicKey);
    const iss = await thumbprint(this.hostKey.publicKey);
    return await new SignJWT({ host_public_key: hostPub })
      .setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
      .setIssuer(iss)
      .setAudience(this.issuerUrl)
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(`h-${randomUUID()}`)
      .sign(this.hostKey.privateKey);
  }

  /** agent+jwt per §4.3. */
  private async mintAgentJwt(aud: string): Promise<string> {
    if (!this.agentKey || !this.agentId) {
      throw new Error("agent key or id not set");
    }
    const iss = await thumbprint(this.hostKey.publicKey);
    return await new SignJWT({})
      .setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
      .setIssuer(iss)
      .setSubject(this.agentId)
      .setAudience(aud)
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(`a-${randomUUID()}`)
      .sign(this.agentKey.privateKey);
  }
}
