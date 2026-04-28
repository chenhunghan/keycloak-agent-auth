package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.SignedJWT;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

/**
 * Realm-scoped REST resource provider for the Agent Auth Protocol.
 *
 * <p>
 * Mounted at: {realm-base-url}/agent-auth/...
 */
public class AgentAuthRealmResourceProvider implements RealmResourceProvider {

  private static final long DEFAULT_AGENT_TTL_SECONDS = 3600L;
  private static final int DEFAULT_APPROVAL_EXPIRES_IN = 600;
  private static final int DEFAULT_APPROVAL_INTERVAL = 10;
  /**
   * Audit B-P1a / spec §8.11: completing approval or denial requires fresh user authentication.
   * Defaults to 5 minutes, configurable per deployment via the
   * {@code agent-auth.approval.max-auth-age-seconds} system property. Used both as the
   * {@code max_age} parameter on the login bounce and as the freshness threshold enforced at POST
   * time.
   */
  private static final long DEFAULT_APPROVAL_MAX_AUTH_AGE_SECONDS = 300L;
  private static final long CLOCK_SKEW_MS = 30_000L;
  private static final int INTROSPECT_UNAUTH_RATE_LIMIT = 100;
  private static final long RATE_LIMIT_WINDOW_MS = 60_000L;
  private static final Set<String> SUPPORTED_CONSTRAINT_OPERATORS = Set.of("max", "min", "in",
      "not_in");
  private static final JwksCache JWKS_CACHE = new JwksCache();
  private static final Map<String, Map<String, Object>> RATE_LIMITS = new ConcurrentHashMap<>();
  private final KeycloakSession session; // NOPMD: will be used by protocol endpoints

  public AgentAuthRealmResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  private AgentAuthStorage storage() {
    return session.getProvider(AgentAuthStorage.class);
  }

  private HostJwtVerifier hostJwtVerifier() {
    return new HostJwtVerifier(storage(), JWKS_CACHE, this::isJtiReplay);
  }

  private AgentJwtVerifier agentJwtVerifier() {
    return new AgentJwtVerifier(storage(), JWKS_CACHE, this::isJtiReplay);
  }

  /**
   * §5.13 catalog auth: distinguish absent-bearer (anonymous public read), malformed-bearer (must
   * surface 401 invalid_jwt), unknown/missing typ (also 401 invalid_jwt), and the two valid typed
   * tokens we route to the typed verifiers. The pre-2026-04 helper collapsed the first four
   * outcomes into the same {@code null}, allowing a malformed Bearer to silently downgrade to
   * anonymous access — a §5.13 violation. Used by the §5.2 catalog endpoints
   * ({@code GET /capability/list}, {@code GET /capability/describe}) so the typed verifiers can
   * produce protocol-correct 401 responses rather than the catalog endpoint silently treating any
   * unparseable token as unauthenticated.
   */
  enum AuthSniff {
    NO_AUTH, MALFORMED, UNSUPPORTED_TYP, HOST_JWT, AGENT_JWT
  }

  private static AuthSniff sniffJwtType(String authHeader) {
    if (authHeader == null || authHeader.isBlank()) {
      return AuthSniff.NO_AUTH;
    }
    if (!authHeader.startsWith("Bearer ")) {
      return AuthSniff.MALFORMED;
    }
    String token = authHeader.substring(7);
    if (token.isBlank()) {
      return AuthSniff.MALFORMED;
    }
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (Exception e) {
      return AuthSniff.MALFORMED;
    }
    if (jwt.getHeader().getType() == null) {
      return AuthSniff.UNSUPPORTED_TYP;
    }
    String typ = jwt.getHeader().getType().getType();
    if ("host+jwt".equals(typ)) {
      return AuthSniff.HOST_JWT;
    }
    if ("agent+jwt".equals(typ)) {
      return AuthSniff.AGENT_JWT;
    }
    return AuthSniff.UNSUPPORTED_TYP;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @GET
  @Path("health")
  @Produces(MediaType.APPLICATION_JSON)
  public Response health() {
    return Response.ok("{\"status\":\"ok\",\"provider\":\"agent-auth\"}").build();
  }

  @POST
  @Path("agent/register")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response registerAgent(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return Response.status(401)
          .entity(Map.of("error", "authentication_required", "message",
              "Missing or invalid Authorization header"))
          .build();
    }

    String token = authHeader.substring(7);
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (Exception e) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt", "message", "Malformed JWT"))
          .build();
    }

    // Validate type
    if (!"host+jwt".equals(jwt.getHeader().getType().getType())) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt", "message", "JWT must be type host+jwt"))
          .build();
    }

    try {
      // Validate presence of required claims
      String jti = jwt.getJWTClaimsSet().getJWTID();
      if (jti == null) {
        return Response.status(401).entity(Map.of("error", "invalid_jwt", "message", "Missing jti"))
            .build();
      }

      if (isJtiReplay(jwt, jti)) {
        return Response.status(401)
            .entity(Map.of("error", "jti_replay", "message", "Replay detected")).build();
      }

      if (jwt.getJWTClaimsSet().getIssueTime() == null) {
        return Response.status(401).entity(Map.of("error", "invalid_jwt", "message", "Missing iat"))
            .build();
      }

      long skewMs = 30_000L;
      if (jwt.getJWTClaimsSet().getIssueTime().getTime() > System.currentTimeMillis() + skewMs) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "JWT issued in the future")).build();
      }

      if (jwt.getJWTClaimsSet().getExpirationTime() == null) {
        return Response.status(401).entity(Map.of("error", "invalid_jwt", "message", "Missing exp"))
            .build();
      }

      long now = System.currentTimeMillis();
      if (now > jwt.getJWTClaimsSet().getExpirationTime().getTime()) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Token expired")).build();
      }

      String expectedAudience = session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
          .path("realms").path(session.getContext().getRealm().getName()).build().toString()
          + "/agent-auth";

      List<String> aud = jwt.getJWTClaimsSet().getAudience();
      if (aud == null || !aud.contains(expectedAudience)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Invalid audience")).build();
      }

      Map<String, Object> hostPublicKeyMap = jwt.getJWTClaimsSet()
          .getJSONObjectClaim("host_public_key");
      String hostJwksUrl = jwt.getJWTClaimsSet().getStringClaim("host_jwks_url");
      if (hostPublicKeyMap != null && hostJwksUrl != null && !hostJwksUrl.isBlank()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message",
                "host_public_key and host_jwks_url are mutually exclusive"))
            .build();
      }
      if (hostPublicKeyMap == null) {
        String hostKid = jwt.getHeader().getKeyID();
        if (hostJwksUrl == null || hostJwksUrl.isBlank()) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message",
                  "Missing host_public_key or host_jwks_url"))
              .build();
        }
        if (hostKid == null || hostKid.isBlank()) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message",
                  "Missing kid for host_jwks_url"))
              .build();
        }
        try {
          hostPublicKeyMap = JWKS_CACHE.resolve(hostJwksUrl, hostKid);
        } catch (IllegalArgumentException e) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message", e.getMessage()))
              .build();
        }
      }

      Map<String, Object> agentPublicKeyMap = jwt.getJWTClaimsSet()
          .getJSONObjectClaim("agent_public_key");
      String agentJwksUrl = jwt.getJWTClaimsSet().getStringClaim("agent_jwks_url");
      if (agentPublicKeyMap != null && agentJwksUrl != null && !agentJwksUrl.isBlank()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message",
                "agent_public_key and agent_jwks_url are mutually exclusive"))
            .build();
      }
      if (agentPublicKeyMap == null) {
        String agentKid = jwt.getJWTClaimsSet().getStringClaim("agent_kid");
        if (agentJwksUrl == null || agentJwksUrl.isBlank()) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message",
                  "Missing agent_public_key or agent_jwks_url"))
              .build();
        }
        if (agentKid == null || agentKid.isBlank()) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message",
                  "Missing agent_kid for agent_jwks_url"))
              .build();
        }
        try {
          agentPublicKeyMap = JWKS_CACHE.resolve(agentJwksUrl, agentKid);
        } catch (IllegalArgumentException e) {
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message", e.getMessage()))
              .build();
        }
      }

      if (!isEd25519Jwk(hostPublicKeyMap)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "host_public_key must be Ed25519"))
            .build();
      }
      if (!isEd25519Jwk(agentPublicKeyMap)) {
        return Response.status(400)
            .entity(Map.of("error", "unsupported_algorithm", "message",
                "Only Ed25519 keys are supported"))
            .build();
      }

      OctetKeyPair hostKey = OctetKeyPair.parse(hostPublicKeyMap);
      JWSVerifier verifier = new Ed25519Verifier(hostKey);
      if (!jwt.verify(verifier)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Invalid signature")).build();
      }

      String iss = jwt.getJWTClaimsSet().getIssuer();
      String thumbprint = hostKey.computeThumbprint().toString();
      if (!thumbprint.equals(iss)) {
        return Response.status(401)
            .entity(
                Map.of("error", "invalid_jwt", "message", "Issuer does not match host thumbprint"))
            .build();
      }

      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      // Check request body
      if (requestBody == null) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
      }

      Object rawName = requestBody.get("name");
      if (!(rawName instanceof String) || ((String) rawName).isBlank()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing required field: name"))
            .build();
      }

      String name = (String) rawName;
      Object rawMode = requestBody.getOrDefault("mode", "delegated");
      if (!(rawMode instanceof String)) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "mode must be a string"))
            .build();
      }
      String mode = (String) rawMode;

      if (!"delegated".equals(mode) && !"autonomous".equals(mode)) {
        return Response.status(400)
            .entity(Map.of("error", "unsupported_mode", "message", "Unsupported mode: " + mode))
            .build();
      }

      Object rawCapabilities = requestBody.getOrDefault("capabilities", List.of());
      if (!(rawCapabilities instanceof List)) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "capabilities must be an array"))
            .build();
      }
      List<?> capabilities = (List<?>) rawCapabilities;
      List<String> invalidCaps = new ArrayList<>();
      List<Map<String, Object>> grants = new ArrayList<>();
      boolean requiresApproval = false;

      // §5.3 / §3.1: per-host TOFU defaults. A delegated agent that requests a capability already
      // in this host's `default_capabilities` auto-grants without re-prompting the user (§5.3:
      // "if the capabilities fall within its defaults, auto-approve"). Loaded before the cap
      // loop so the per-grant status decision can consult it.
      // §2.11: "any agent registered under a `pending` host MUST remain `pending` until the
      // host is approved." Compute the host's effective state (loaded record's status, or
      // `pending` for the new-host case which is created below) so the cap loop can force
      // every grant pending alongside the agent itself.
      String hostId = iss;
      Map<String, Object> hostData = storage().getHost(hostId);
      List<String> hostDefaults = hostDefaultCapabilities(hostData);
      boolean hostPending = hostData == null || "pending".equals(hostData.get("status"));

      for (Object capObj : capabilities) {
        String capName;
        Map<String, Object> requestedConstraints = null;
        if (capObj instanceof String) {
          capName = (String) capObj;
        } else if (capObj instanceof Map) {
          Map<?, ?> capMap = (Map<?, ?>) capObj;
          Object rawCapName = capMap.get("name");
          if (!(rawCapName instanceof String) || ((String) rawCapName).isBlank()) {
            return Response.status(400)
                .entity(Map.of("error", "invalid_request",
                    "message", "Capability object must include a non-empty name"))
                .build();
          }
          capName = (String) rawCapName;
          Object rawConstraints = capMap.get("constraints");
          if (rawConstraints != null) {
            if (!(rawConstraints instanceof Map)) {
              return Response.status(400)
                  .entity(Map.of("error", "invalid_request",
                      "message", "constraints must be an object"))
                  .build();
            }
            requestedConstraints = (Map<String, Object>) rawConstraints;
          }
        } else {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request",
                  "message", "Each capability must be a string or object"))
              .build();
        }

        if (capName.isBlank()) {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request", "message", "Capability name is empty"))
              .build();
        }

        Map<String, Object> registeredCap = storage().getCapability(capName);
        if (registeredCap == null) {
          invalidCaps.add(capName);
        } else {
          List<String> unknownOperators = unknownConstraintOperators(requestedConstraints);
          if (!unknownOperators.isEmpty()) {
            return unknownConstraintOperatorResponse(unknownOperators);
          }

          boolean capReqApproval = Boolean.TRUE.equals(registeredCap.get("requires_approval"));
          boolean autoDeny = Boolean.TRUE.equals(registeredCap.get("auto_deny"));
          // §5.3: TOFU auto-grant — a cap that's already in the host's defaults auto-approves
          // even if the cap registry says requires_approval=true, because the linked user has
          // approved it for this host before.
          // §2.11: pending host forces every grant pending too — needsApproval kept true so the
          // approval flow runs and this agent's grants land alongside the host activation.
          boolean inHostDefaults = hostDefaults.contains(capName);
          boolean needsApproval = hostPending || (capReqApproval && !inHostDefaults);
          // Only mark as requiring approval if not auto-denied.
          if (needsApproval && !autoDeny)
            requiresApproval = true;

          Map<String, Object> grant = new HashMap<>();
          grant.put("capability", capName);
          if (autoDeny) {
            grant.put("status", "denied");
            grant.put("reason", "Capability has auto_deny enabled");
          } else if (needsApproval) {
            grant.put("status", "pending");
          } else {
            grant.put("status", "active");
            grant.put("description", registeredCap.get("description"));
            if (registeredCap.containsKey("input")) {
              grant.put("input", registeredCap.get("input"));
            }
            if (registeredCap.containsKey("output")) {
              grant.put("output", registeredCap.get("output"));
            }
            grant.put("granted_by", iss);
          }
          // §2.13: "the server MUST NOT widen constraints beyond what the agent requested
          // without new approval." For active grants we record `constraints` directly. For
          // pending grants we stash the requested scope in `requested_constraints` so the
          // pending response stays compact (§5.3 / §5.4) while the approval activation can
          // restore the originally-requested scope into `constraints` — without this, a
          // pending grant promoted to active would lose its scope and become broader than
          // the agent ever asked for.
          if (requestedConstraints != null) {
            if ("pending".equals(grant.get("status"))) {
              grant.put("requested_constraints", requestedConstraints);
            } else if (!"denied".equals(grant.get("status"))) {
              grant.put("constraints", requestedConstraints);
            }
          }
          grants.add(grant);
        }
      }

      // Prevent duplicate active agents — host data was loaded above before the cap loop so the
      // §5.3 host-defaults auto-grant decision and the entitlement gate below can both read it.
      String agentKeyThumb = OctetKeyPair.parse(agentPublicKeyMap).computeThumbprint().toString();

      // Phase 1 user-entitlement gate at register: caps with org/role gates are only assignable
      // when the host's owning user satisfies them. Without this, autonomous agents (or any flow
      // that ends with status=active grants because requires_approval=false) could mint a grant
      // by naming a cap whose org the owner isn't a member of — bypassing the visibility filter
      // on /capability/list. For delegated agents on unlinked hosts the existing approval flow
      // gates by approver entitlement, so the register-time gate is skipped there to preserve
      // today's behavior. Autonomous agents are always gated (no approval flow to catch later).
      String hostOwnerForGate = hostData == null ? null : (String) hostData.get("user_id");
      boolean shouldRunRegisterGate = "autonomous".equals(mode)
          || (hostOwnerForGate != null && !hostOwnerForGate.isBlank());
      if (shouldRunRegisterGate) {
        UserEntitlement hostOwnerEntitlement = loadUserEntitlement(hostOwnerForGate);
        List<Map<String, Object>> entitledGrants = new ArrayList<>();
        for (Map<String, Object> grant : grants) {
          String capName = (String) grant.get("capability");
          Map<String, Object> registeredCap = storage().getCapability(capName);
          if (registeredCap != null
              && !userEntitlementAllows(registeredCap, hostOwnerEntitlement)) {
            invalidCaps.add(capName);
            continue;
          }
          entitledGrants.add(grant);
        }
        grants = entitledGrants;
      }

      if (!invalidCaps.isEmpty()) {
        return Response.status(400).entity(Map.of("error", "invalid_capabilities", "message",
            "Invalid capabilities", "invalid_capabilities", invalidCaps)).build();
      }
      if (hostData != null) {
        String hostStatus = (String) hostData.get("status");
        if ("revoked".equals(hostStatus)) {
          return Response.status(403)
              .entity(Map.of("error", "host_revoked", "message", "Host is revoked")).build();
        }
        if ("rejected".equals(hostStatus)) {
          return Response.status(403)
              .entity(Map.of("error", "host_rejected", "message", "Host is rejected")).build();
        }
        // SA-host + delegated is a misconfiguration: the SA user has no human consent
        // channel, so a CIBA-email or device-flow approval would never land and the agent
        // would be stuck `pending`. Hosts pre-registered with `client_id` must run
        // autonomous-mode agents.
        if (hostData.get("service_account_client_id") != null && "delegated".equals(mode)) {
          return Response.status(400)
              .entity(Map.of("error", "invalid_mode_for_sa_host",
                  "message",
                  "Host is bound to a service-account client; "
                      + "agents under SA-hosts must use mode=autonomous"))
              .build();
        }
      }

      Map<String, Object> existingAgent = storage().findAgentByKeyAndHost(agentKeyThumb, hostId);
      if (existingAgent != null) {
        String existingStatus = (String) existingAgent.get("status");
        if ("active".equals(existingStatus)) {
          return Response.status(409)
              .entity(Map.of("error", "agent_exists", "message", "Agent already exists")).build();
        } else if ("pending".equals(existingStatus)) {
          // Return existing pending agent (sanitized — pending grants stash requested
          // constraints internally but the wire shape stays compact per §5.3).
          return Response.ok(sanitizeAgentResponse(existingAgent)).build();
        } else if ("revoked".equals(existingStatus) || "rejected".equals(existingStatus)
            || "claimed".equals(existingStatus)) {
          return Response.status(409)
              .entity(Map.of("error", "agent_exists", "message",
                  "Agent already exists in a terminal state"))
              .build();
        }
      }

      // §2.8: a host first seen via dynamic registration is created in `pending` state.
      // Autonomous agents can't be bootstrapped under a pending host because there's no
      // user-approval flow for them — reject early so admins are forced down the spec's
      // pre-registration path (§2.8 path #2).
      if (hostData == null && "autonomous".equals(mode)) {
        return Response.status(400)
            .entity(Map.of("error", "host_pre_registration_required",
                "message",
                "Autonomous agents require a pre-registered host (§2.8); dynamic registration"
                    + " on an unknown host produces a `pending` host state and §2.11 forbids"
                    + " the autonomous agent from activating without an approval flow."))
            .build();
      }

      String agentId = UUID.randomUUID().toString();
      // §2.11 MUST: pending host → pending agent. Otherwise the existing approval-routing rule
      // applies: delegated + needsApproval → pending; everything else → active.
      String status = (hostPending || ("delegated".equals(mode) && requiresApproval))
          ? "pending"
          : "active";
      String nowTs = nowTimestamp();

      Map<String, Object> agentData = new HashMap<>();
      agentData.put("agent_id", agentId);
      agentData.put("host_id", hostId);
      agentData.put("agent_key_thumbprint", agentKeyThumb);
      agentData.put("agent_public_key", agentPublicKeyMap);
      if (agentJwksUrl != null && !agentJwksUrl.isBlank()) {
        agentData.put("agent_jwks_url", agentJwksUrl);
        agentData.put("agent_kid", jwt.getJWTClaimsSet().getStringClaim("agent_kid"));
      }
      agentData.put("name", name);
      agentData.put("mode", mode);
      agentData.put("status", status);
      agentData.put("agent_capability_grants", grants);
      agentData.put("created_at", nowTs);
      agentData.put("updated_at", nowTs);
      agentData.put("expires_at", futureTimestamp(DEFAULT_AGENT_TTL_SECONDS));

      if ("pending".equals(status)) {
        String bindingMessage = requestBody.get("binding_message") instanceof String bm
            ? bm
            : null;
        agentData.put("approval",
            selectApprovalObject(agentId, agentData, hostData, mode, bindingMessage));
        // §5.3 / §5.4: pending grants on the wire are compact {capability, status} objects. The
        // per-grant status URL is published as a documented extension at
        // GET /agent/{agentId}/capabilities/{capabilityName}/status — it must NOT appear inside
        // the grant object itself. We deliberately don't stamp it on the stored grant.
      } else {
        agentData.put("activated_at", nowTs);
      }

      if (hostData == null) {
        hostData = new HashMap<>();
        hostData.put("host_id", hostId);
        hostData.put("public_key", hostPublicKeyMap);
        if (hostJwksUrl != null && !hostJwksUrl.isBlank()) {
          hostData.put("host_jwks_url", hostJwksUrl);
          hostData.put("host_kid", jwt.getHeader().getKeyID());
        }
        // §2.8: dynamic registration creates the host in `pending` state pending user approval.
        // The first /verify/approve (or admin approve) flips it to `active` alongside the
        // host→user link. Pre-registration via the admin API is the alternate path that creates
        // hosts directly active.
        hostData.put("status", "pending");
        hostData.put("created_at", nowTs);
        hostData.put("default_capability_grants", copyGrantDefaults(grants));
      }
      hostData.put("updated_at", nowTs);
      hostData.put("last_used_at", nowTs);
      storage().putHost(hostId, hostData);

      // §3.2: agent.user_id is "set from the host's user_id or session auth." Delegated agents
      // registered under an already-linked host inherit the host's user_id at creation time,
      // matching the cascade the admin link handler performs for pre-existing agents.
      if ("delegated".equals(mode) && hostData.get("user_id") != null) {
        agentData.put("user_id", hostData.get("user_id"));
      }

      storage().putAgent(agentId, agentData);

      return Response.ok(sanitizeAgentResponse(agentData)).build();

    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("agent/introspect")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response introspect(
      @HeaderParam("Authorization") String authHeader,
      @HeaderParam("X-AgentAuth-Resource-Server-Token") String rsTokenHeader,
      Map<String, Object> requestBody) {
    // Audit E-F1 / §5.13: rate-limit MUST be non-bypassable. The pre-fix logic gated the limiter
    // on "Authorization header missing or non-Bearer", so any caller could send `Bearer <any
    // parseable jwt>` to skip the limit without authenticating. We now apply the unauthenticated
    // limiter unconditionally unless we positively verify a real resource-server credential.
    //
    // Minimum viable RS-auth: a shared secret configured via `agent-auth.introspect.shared-secret`.
    // The caller may send it via `X-AgentAuth-Resource-Server-Token: <secret>` OR
    // `Authorization: Bearer <secret>`. If the property is unset or empty, no caller is ever
    // authenticated and the limiter always applies.
    //
    // TODO(audit-followup): replace the shared-secret stopgap with real RS auth (mTLS or
    // Keycloak service-account/client-credentials validation).
    boolean resourceServerAuthenticated = false;
    String configuredSecret = System.getProperty("agent-auth.introspect.shared-secret");
    if (configuredSecret != null && !configuredSecret.isEmpty()) {
      String presentedSecret = null;
      if (rsTokenHeader != null && !rsTokenHeader.isBlank()) {
        presentedSecret = rsTokenHeader.trim();
      } else if (authHeader != null && authHeader.startsWith("Bearer ")) {
        // Constant-time comparison would be ideal; with a small fixed-length secret per deployment,
        // a TODO-grade equality check is acceptable for the stopgap. Real RS auth will replace
        // this.
        presentedSecret = authHeader.substring(7).trim();
      }
      if (presentedSecret != null && presentedSecret.equals(configuredSecret)) {
        resourceServerAuthenticated = true;
      }
    }

    // Test-mode escape hatch: when `agent-auth.test-mode=true` is set on the JVM (only by the
    // testcontainers harness, see TestcontainersSupport), the unauthenticated rate-limiter is
    // skipped so the integration suite can introspect freely without configuring a shared secret
    // or per-test header. The production path (no test-mode) keeps the new non-bypassable limit.
    boolean testModeBypass = "true".equals(System.getProperty("agent-auth.test-mode"));

    if (!resourceServerAuthenticated && !testModeBypass) {
      Response rateLimited = enforceRateLimit("introspect:unauthenticated",
          INTROSPECT_UNAUTH_RATE_LIMIT, RATE_LIMIT_WINDOW_MS);
      if (rateLimited != null) {
        return rateLimited;
      }
    }

    // Authorization-header parse-check is unrelated to resource-server auth: it only catches a
    // malformed Bearer that some clients used to send. If the configured shared secret matched a
    // Bearer token above, treat the header as resource-server credential and don't try to parse.
    if (!resourceServerAuthenticated
        && authHeader != null && authHeader.startsWith("Bearer ")) {
      try {
        SignedJWT.parse(authHeader.substring(7));
      } catch (Exception e) {
        return Response.status(401).entity(
            Map.of("error", "invalid_jwt", "message", "Malformed Authorization JWT")).build();
      }
    }

    if (requestBody == null || !requestBody.containsKey("token")) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing token")).build();
    }

    // Audit E-F5 / §5.13: malformed body — non-string or blank `token` — must yield
    // 400 invalid_request, not silently fall through the broad catch and return {active: false}.
    Object rawToken = requestBody.get("token");
    if (!(rawToken instanceof String) || ((String) rawToken).isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "token must be a non-blank string"))
          .build();
    }
    String token = (String) rawToken;
    try {
      SignedJWT jwt = SignedJWT.parse(token);
      if (!"agent+jwt".equals(jwt.getHeader().getType().getType())) {
        return Response.ok(Map.of("active", false)).build();
      }

      String jti = jwt.getJWTClaimsSet().getJWTID();
      if (jti == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      String agentId = jwt.getJWTClaimsSet().getSubject();
      if (agentId == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      // §§2.3-2.5: lazy lifecycle-clock evaluation. A token may arrive while the stored status
      // still says `active`; the centralised evaluator demotes it before we treat it as such.
      String statusBeforeIntrospectClock = (String) agentData.get("status");
      LifecycleClock.Result introspectClock = LifecycleClock.applyExpiry(agentData);
      if (introspectClock != LifecycleClock.Result.ACTIVE
          && !java.util.Objects.equals(statusBeforeIntrospectClock, agentData.get("status"))) {
        agentData.put("updated_at", nowTimestamp());
        storage().putAgent(agentId, agentData);
      }

      if (!"active".equals(agentData.get("status"))) {
        return Response.ok(Map.of("active", false)).build();
      }

      Map<String, Object> agentPublicKeyMap = resolveAgentPublicKeyMap(agentData, jwt);
      if (agentPublicKeyMap == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      OctetKeyPair agentKey = OctetKeyPair.parse(agentPublicKeyMap);
      JWSVerifier verifier = new Ed25519Verifier(agentKey);
      if (!jwt.verify(verifier)) {
        return Response.ok(Map.of("active", false)).build();
      }

      if (jwt.getJWTClaimsSet().getExpirationTime() == null
          || jwt.getJWTClaimsSet().getIssueTime() == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      long now = System.currentTimeMillis();
      if (now > jwt.getJWTClaimsSet().getExpirationTime().getTime()) {
        return Response.ok(Map.of("active", false)).build();
      }

      long skewMsIntrospect = 30_000L;
      if (jwt.getJWTClaimsSet().getIssueTime().getTime() > now + skewMsIntrospect) {
        return Response.ok(Map.of("active", false)).build();
      }

      // §4.3: an agent+jwt's `aud` MUST be the resolved location URL — `capability.location` if
      // set, else `default_location` (which our discovery advertises as
      // `<issuer>/capability/execute`). Agent+jwts only authorize execution, so introspectable
      // tokens are always execution tokens. Accept the token if its `aud` matches the resolved
      // location URL of any capability the agent currently holds an active grant for, optionally
      // narrowed by the JWT's `capabilities` claim. This binds aud-acceptance to the agent's
      // actual surface — a token minted with aud=X for a cap the agent doesn't hold isn't valid
      // at the resource server anyway, so admitting it here would only mislead the caller.
      String defaultLocation = issuerUrl() + "/capability/execute";
      List<String> aud = jwt.getJWTClaimsSet().getAudience();
      if (aud == null || aud.isEmpty()) {
        return Response.ok(Map.of("active", false)).build();
      }
      List<Map<String, Object>> grantsForAud = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      List<String> jwtCapClaim = null;
      Object rawJwtCaps = jwt.getJWTClaimsSet().getClaim("capabilities");
      if (rawJwtCaps instanceof List<?> raw) {
        jwtCapClaim = new ArrayList<>();
        for (Object item : raw) {
          if (item instanceof String s) {
            jwtCapClaim.add(s);
          }
        }
      }
      boolean audMatchesAGrant = false;
      Instant grantNow = Instant.now();
      if (grantsForAud != null) {
        for (Map<String, Object> grant : grantsForAud) {
          // Audit E-F4 / §3.3: effective grants must be active AND not past expires_at.
          if (!isEffectiveActiveGrant(grant, grantNow)) {
            continue;
          }
          String grantCapName = (String) grant.get("capability");
          if (jwtCapClaim != null && !jwtCapClaim.contains(grantCapName)) {
            continue;
          }
          Map<String, Object> capForAud = storage().getCapability(grantCapName);
          if (capForAud == null) {
            continue;
          }
          String capLoc = (String) capForAud.get("location");
          String resolved = (capLoc != null && !capLoc.isBlank()) ? capLoc : defaultLocation;
          if (aud.contains(resolved)) {
            audMatchesAGrant = true;
            break;
          }
        }
      }
      if (!audMatchesAGrant) {
        return Response.ok(Map.of("active", false)).build();
      }

      // Build valid response
      String issInJwt = jwt.getJWTClaimsSet().getIssuer();
      if (issInJwt == null) {
        return Response.ok(Map.of("active", false)).build();
      }

      // Audit E-F6 (deferred): exact-match `iss == agent.host_id` is correct for inline-key hosts
      // but does not honour the JWKS host-rotation fallback that {@link AgentJwtVerifier#verify}
      // applies in Wave 1 (rebinds the verified iss to the rotated host's id). Migrating
      // /agent/introspect to {@code agentJwtVerifier().verify(...)} requires reshaping the
      // selectedGrant / constraint-check / scope/mode response builder; deferred to a follow-up.
      String hostId = (String) agentData.get("host_id");
      if (!hostId.equals(issInJwt)) {
        return Response.ok(Map.of("active", false)).build();
      }

      Map<String, Object> hostDataForAgent = storage().getHost(hostId);
      if (hostDataForAgent == null || !"active".equals(hostDataForAgent.get("status"))) {
        return Response.ok(Map.of("active", false)).build();
      }

      // §4.5 + §4.6: jti replay detection MUST run AFTER signature verification and identity/
      // state validation. Otherwise a forged or stale-state token with a guessed jti could
      // burn that jti before the legitimate signed token is processed, denying the legitimate
      // agent its single-use credential.
      if (isJtiReplay(jwt, jti)) {
        return Response.ok(Map.of("active", false)).build();
      }

      // Update last_used_at on successful introspect
      agentData.put("last_used_at", nowTimestamp());
      storage().putAgent(agentId, agentData);

      String mode = (String) agentData.get("mode");

      Map<String, Object> extraClaims = jwt.getJWTClaimsSet().getClaims();
      List<String> restrictedCaps = null;
      if (extraClaims.containsKey("capabilities")) {
        restrictedCaps = (List<String>) extraClaims.get("capabilities");
      }

      List<Map<String, Object>> allGrants = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      List<Map<String, Object>> returnedGrants = new ArrayList<>();
      List<String> scopeList = new ArrayList<>();
      // §5.12 + audit-04 P1: the entitlement-filtered active-grant set is the ONLY grant pool
      // the {capability, arguments} extension may resolve against. Falling back to any stored
      // grant (regardless of status/entitlement) when the requested capability is missing here
      // would let constraint checks run on the wrong grant, returning empty `violations` for a
      // token that should not be allowed. We track active grants by name in a parallel map so
      // the extension lookup below cannot accidentally widen the search to the raw `allGrants`.
      Map<String, Map<String, Object>> activeGrantsByName = new HashMap<>();

      // Phase 2 of the multi-tenant authz plan: lazy re-evaluation of the layer-2 gate against
      // the agent's user. Q4 cascade is hybrid — eager on org-membership changes (Phase 4),
      // lazy on role drift. Until Phase 4 lands, both paths are caught here: grants whose cap
      // requires an org/role the agent's user no longer satisfies are stripped from the
      // response. The grant row stays in storage (revocation is the cascade's job), but it
      // becomes invisible to resource servers via introspect.
      String agentUserId = (String) agentData.get("user_id");
      UserEntitlement agentUserEntitlement = loadUserEntitlement(agentUserId);

      if (allGrants != null) {
        for (Map<String, Object> grant : allGrants) {
          // Audit E-F4 / §3.3: effective grants must be active AND not past expires_at.
          if (!isEffectiveActiveGrant(grant, grantNow))
            continue;
          String capName = (String) grant.get("capability");
          if (restrictedCaps != null && !restrictedCaps.contains(capName))
            continue;

          Map<String, Object> registeredCap = storage().getCapability(capName);
          if (registeredCap == null
              || !userEntitlementAllows(registeredCap, agentUserEntitlement)) {
            continue;
          }

          Map<String, Object> compactGrant = new HashMap<>();
          compactGrant.put("capability", capName);
          compactGrant.put("status", grant.get("status"));
          returnedGrants.add(compactGrant);
          scopeList.add(capName);
          activeGrantsByName.put(capName, grant);
        }
      }

      // §5.12 introspection extension: resolve {capability, arguments} ONLY against the
      // entitlement-filtered active-grant set built above. If the requested capability is not
      // in that set, return an extension-shaped {active: false, error: "capability_not_granted"}
      // response — never silently fall back to a different grant.
      Object requestedCapability = requestBody.get("capability");
      Object rawArguments = requestBody.get("arguments");
      String requestedCapabilityName = null;
      if (requestedCapability instanceof String s && !s.isBlank()) {
        requestedCapabilityName = s;
      }

      Map<String, Object> selectedGrant = null;
      if (requestedCapabilityName != null) {
        selectedGrant = activeGrantsByName.get(requestedCapabilityName);
        if (selectedGrant == null) {
          return Response.ok(Map.of(
              "active", false,
              "error", "capability_not_granted")).build();
        }
      }

      // Validate `arguments` shape early so we can return 400 before building the response, and
      // so the constraint-check extension below can rely on a typed Map.
      Map<String, Object> argumentsMap = null;
      if (rawArguments != null) {
        if (!(rawArguments instanceof Map<?, ?>)) {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request", "message", "arguments must be an object"))
              .build();
        }
        argumentsMap = (Map<String, Object>) rawArguments;
      }

      Map<String, Object> response = new HashMap<>();
      response.put("active", true);
      response.put("agent_id", agentId);
      response.put("host_id", hostId);
      // §5.12: agent_capability_grants is compact — {capability, status} only. Constraints and
      // their evaluation outcome are extension-only (see `extensions.constraint_check` below).
      response.put("agent_capability_grants", returnedGrants);
      response.put("sub", agentId);
      response.put("iss", hostId);
      response.put("client_id", hostId);
      response.put("scope", String.join(" ", scopeList));
      response.put("exp", jwt.getJWTClaimsSet().getExpirationTime().getTime() / 1000);
      response.put("iat", jwt.getJWTClaimsSet().getIssueTime().getTime() / 1000);
      response.put("mode", mode);
      response.put("expires_at", agentData.get("expires_at"));
      response.put("capabilities", returnedGrants);
      response.put("aud", aud.size() == 1 ? aud.get(0) : aud);
      response.put("jti", jti);

      // §5.12: active introspection includes user_id when the host is linked. Prefer the agent's
      // user_id (set at registration for delegated agents under linked hosts), fall back to the
      // host's user_id when the agent row hasn't picked it up yet.
      Object userIdForResponse = agentData.get("user_id");
      if (userIdForResponse == null) {
        userIdForResponse = hostDataForAgent.get("user_id");
      }
      if (userIdForResponse != null) {
        response.put("user_id", userIdForResponse);
      }

      // {capability, arguments} extension — emit constraint-check outcome under an extension key,
      // NOT as a top-level `constraints`/`violations` block on the base response. The compact
      // grant list (above) carries no constraint data.
      //
      // Audit E-F7 (spec-aligned shape per README direct-mode resource server contract): we ALSO
      // mirror the violations list at top level so direct-mode resource servers can simply check
      // {@code body.violations.length === 0} per the README example. The extension key remains for
      // backward compatibility with clients already reading it. When constraint-check is invoked
      // and there are no violations, the top-level key is present as an empty list (`[]`) so the
      // README's "violations is present and non-empty" rule has a stable presence signal. When
      // constraint-check is NOT invoked (no `arguments` and no `capability` selector), the
      // top-level key is omitted entirely — there is nothing to check against.
      if (selectedGrant != null) {
        Map<String, Object> constraintCheck = new HashMap<>();
        constraintCheck.put("capability", selectedGrant.get("capability"));
        if (selectedGrant.containsKey("constraints")) {
          constraintCheck.put("constraints", selectedGrant.get("constraints"));
        }
        List<Map<String, Object>> violationMapsForTopLevel = null;
        if (argumentsMap != null) {
          List<Map<String, Object>> violationMaps = new ArrayList<>();
          if (selectedGrant.containsKey("constraints")) {
            List<ConstraintViolation> violations = new ConstraintValidator().validate(
                (Map<String, Object>) selectedGrant.get("constraints"),
                argumentsMap);
            for (ConstraintViolation v : violations) {
              Map<String, Object> vmap = new HashMap<>();
              vmap.put("field", v.field());
              vmap.put("constraint", v.constraint());
              vmap.put("actual", v.actual());
              violationMaps.add(vmap);
            }
          }
          constraintCheck.put("violations", violationMaps);
          violationMapsForTopLevel = violationMaps;
        }
        Map<String, Object> extensions = new HashMap<>();
        extensions.put("constraint_check", constraintCheck);
        response.put("extensions", extensions);
        // Top-level mirror — only when constraint-check actually ran (i.e. arguments were
        // supplied). Empty list signals "constraints checked, none violated"; omission signals
        // "constraint-check did not run on this request".
        if (violationMapsForTopLevel != null) {
          response.put("violations", violationMapsForTopLevel);
        }
      }

      return Response.ok(response).build();
    } catch (Exception e) {
      return Response.ok(Map.of("active", false)).build();
    }
  }

  @GET
  @Path("agent/status")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getAgentStatus(
      @HeaderParam("Authorization") String authHeader,
      @QueryParam("agent_id") String agentId) {

    HostJwtVerifier verifier = hostJwtVerifier();
    HostJwtVerifier.Result verified;
    try {
      verified = verifier.verify(authHeader, issuerUrl(), HostJwtVerifier.Options.forAgentStatus());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      Map<String, Object> hostData = verified.hostData();

      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      // Check host revocation BEFORE jti replay, so a revoked host gets 403 immediately
      // even if the same JWT was used for the revoke call (jti already consumed).
      if (hostData != null && "revoked".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_revoked", "message", "Host is revoked")).build();
      }

      // For unknown host keys, we still need to handle the request gracefully:
      // - missing agent_id → 400
      // - nonexistent agent → 404
      // - agent belongs to a different host → 403
      // - agent belongs to this same host (key rotated away) → 401 invalid_jwt
      if (hostData == null) {
        if (agentId == null) {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request", "message", "Missing agent_id")).build();
        }
        Map<String, Object> agentDataForUnknownHost = storage().getAgent(agentId);
        if (agentDataForUnknownHost == null) {
          return Response.status(404)
              .entity(Map.of("error", "agent_not_found", "message", "Agent not found")).build();
        }
        if (iss.equals(agentDataForUnknownHost.get("host_id"))) {
          // same host thumbprint but no longer registered (e.g. stale key after rotation)
          return Response.status(401)
              .entity(Map.of("error", "invalid_jwt", "message", "Unknown host key")).build();
        }
        // agent belongs to a different host
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch")).build();
      }

      try {
        verifier.enforceJtiReplay(verified);
      } catch (HostJwtException e) {
        return e.response();
      }

      if (agentId == null) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing agent_id")).build();
      }

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(404)
            .entity(Map.of("error", "agent_not_found", "message", "Agent not found")).build();
      }

      if (!iss.equals(agentData.get("host_id"))) {
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch")).build();
      }

      // §§2.3-2.5: lifecycle clocks are evaluated lazily on read so a status snapshot reflects
      // the current state even when no other path has had a chance to mutate the record. Persist
      // any status transition so subsequent calls see the new value.
      String statusBeforeStatusClock = (String) agentData.get("status");
      LifecycleClock.Result statusClock = LifecycleClock.applyExpiry(agentData);
      if (statusClock != LifecycleClock.Result.ACTIVE
          && !java.util.Objects.equals(statusBeforeStatusClock, agentData.get("status"))) {
        agentData.put("updated_at", nowTimestamp());
        storage().putAgent(agentId, agentData);
      }

      return Response.ok(sanitizeAgentResponse(agentData)).build();
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("agent/rotate-key")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response rotateAgentKey(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      if (requestBody == null || !requestBody.containsKey("agent_id")
          || !requestBody.containsKey("public_key")) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing agent_id or public_key"))
            .build();
      }

      String agentId = (String) requestBody.get("agent_id");
      Object pubKeyObj = requestBody.get("public_key");
      if (!(pubKeyObj instanceof Map)) {
        return Response.status(400)
            .entity(
                Map.of("error", "invalid_request", "message", "public_key must be a JWK object"))
            .build();
      }

      @SuppressWarnings("unchecked")
      Map<String, Object> newAgentPublicKeyMap = (Map<String, Object>) pubKeyObj;
      OctetKeyPair newAgentKey;
      try {
        newAgentKey = OctetKeyPair.parse(newAgentPublicKeyMap);
      } catch (Exception e) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Malformed JWK")).build();
      }

      if (!com.nimbusds.jose.jwk.Curve.Ed25519.equals(newAgentKey.getCurve())) {
        return Response.status(400)
            .entity(Map.of("error", "unsupported_algorithm", "message",
                "Only Ed25519 keys are supported"))
            .build();
      }

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(404)
            .entity(Map.of("error", "agent_not_found", "message", "Agent not found")).build();
      }

      if (!iss.equals(agentData.get("host_id"))) {
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch")).build();
      }

      // §4.5.1: non-registration host calls require an active host record. Mirror the guard
      // applied in revokeAgent / reactivateAgent so a self-signed JWT for a pending or revoked
      // host can't mutate agent keys.
      Map<String, Object> hostData = verified.hostData();
      if (hostData == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Unknown host key"))
            .build();
      }
      if ("revoked".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
            .build();
      }
      if ("pending".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_pending", "message", "Host is pending"))
            .build();
      }

      String status = (String) agentData.get("status");
      if ("revoked".equals(status) || "rejected".equals(status) || "claimed".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_revoked", "message", "Agent is in a terminal state"))
            .build();
      }

      // §5.8: rotate-key transitions agent status to `active` per the response contract.
      // A pending agent has no §2.8-approved owner so a key rotation would silently bypass the
      // approval flow — reject it for the same reason rotateHostKey rejects pending hosts.
      if ("pending".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_pending", "message", "Agent is pending"))
            .build();
      }

      if ("expired".equals(status)) {
        return Response.status(403).entity(Map.of("error", "agent_expired", "message",
            "Cannot rotate key for expired agent without reactivation")).build();
      }

      agentData.put("agent_public_key", newAgentPublicKeyMap);
      agentData.put("agent_key_thumbprint", newAgentKey.computeThumbprint().toString());
      storage().putAgent(agentId, agentData);

      // §5.8 wire shape: rotate-key response is exactly {agent_id, status}. status is `active`
      // since pre-mutation status is guaranteed `active` here (all other states rejected above).
      return Response.ok(Map.of("agent_id", agentId, "status", agentData.get("status"))).build();
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("agent/revoke")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response revokeAgent(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      if (requestBody == null || !requestBody.containsKey("agent_id")) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing agent_id")).build();
      }

      String agentId = (String) requestBody.get("agent_id");

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(404)
            .entity(Map.of("error", "agent_not_found", "message", "Agent not found")).build();
      }

      if (!iss.equals(agentData.get("host_id"))) {
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch")).build();
      }

      Map<String, Object> hostData = verified.hostData();
      if (hostData == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Unknown host key"))
            .build();
      }
      if ("revoked".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
            .build();
      }
      if ("pending".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_pending", "message", "Host is pending"))
            .build();
      }

      // §5.7 wire shape: revoke response is exactly {agent_id, status}. Idempotent on
      // already-revoked agents — return 200 with the same shape rather than 409, matching the
      // host-revoke semantics in revokeHost.
      if ("revoked".equals(agentData.get("status"))) {
        return Response.ok(Map.of("agent_id", agentId, "status", "revoked")).build();
      }

      agentData.put("status", "revoked");
      if (requestBody.containsKey("reason")) {
        agentData.put("revocation_reason", requestBody.get("reason"));
      }
      storage().putAgent(agentId, agentData);

      return Response.ok(Map.of("agent_id", agentId, "status", "revoked")).build();
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("agent/reactivate")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response reactivateAgent(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      if (requestBody == null || !requestBody.containsKey("agent_id")) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing agent_id")).build();
      }

      String agentId = (String) requestBody.get("agent_id");
      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(404)
            .entity(Map.of("error", "agent_not_found", "message", "Agent not found")).build();
      }

      if (!iss.equals(agentData.get("host_id"))) {
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch")).build();
      }

      Map<String, Object> hostData = verified.hostData();
      if (hostData == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Unknown host key"))
            .build();
      }
      if ("revoked".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
            .build();
      }
      if ("pending".equals(hostData.get("status"))) {
        return Response.status(403)
            .entity(Map.of("error", "host_pending", "message", "Host is pending"))
            .build();
      }

      String status = (String) agentData.get("status");
      if ("revoked".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_revoked", "message", "Agent is revoked")).build();
      }
      if ("rejected".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_rejected", "message", "Agent is rejected")).build();
      }
      if ("claimed".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_claimed", "message", "Agent is claimed")).build();
      }
      if ("pending".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_pending", "message", "Agent is pending")).build();
      }

      if ("active".equals(status)) {
        return Response.ok(sanitizeAgentResponse(agentData)).build();
      }

      if ("expired".equals(status)) {
        // §5.6 step 2 + §2.4: absolute lifetime is computed against the agent's original
        // timestamps (or the legacy hard-flag), not the lazy `applyExpiry` shortcut. Re-running
        // `evaluate` here means a backdated `created_at` tips the agent into permanent revoked
        // state instead of being silently reactivated.
        if (LifecycleClock
            .evaluate(agentData) == LifecycleClock.Result.ABSOLUTE_LIFETIME_EXCEEDED) {
          agentData.put("status", "revoked");
          agentData.putIfAbsent("revocation_reason", "absolute_lifetime_exceeded");
          agentData.put("updated_at", nowTimestamp());
          storage().putAgent(agentId, agentData);
          return Response.status(403)
              .entity(Map.of("error", "absolute_lifetime_exceeded", "message",
                  "Absolute lifetime has elapsed"))
              .build();
        }

        // Reset session TTL and max lifetime clocks
        String nowTs = nowTimestamp();
        agentData.put("session_ttl_reset_at", System.currentTimeMillis());
        agentData.put("max_lifetime_reset_at", System.currentTimeMillis());
        agentData.put("updated_at", nowTs);
        agentData.put("activated_at", nowTs);
        agentData.put("expires_at", futureTimestamp(DEFAULT_AGENT_TTL_SECONDS));

        List<Map<String, Object>> grants = buildReactivationGrants(hostData);
        agentData.put("agent_capability_grants", grants);

        boolean needsApproval = false;
        for (Map<String, Object> grant : grants) {
          if ("pending".equals(grant.get("status"))) {
            needsApproval = true;
          }
        }

        if (needsApproval) {
          agentData.put("status", "pending");
          agentData.put("approval", selectApprovalObject(
              (String) agentData.get("agent_id"), agentData, hostData,
              (String) agentData.get("mode"), null));
        } else {
          agentData.put("status", "active");
          agentData.remove("approval");
        }
        storage().putAgent(agentId, agentData);
        return Response.ok(sanitizeAgentResponse(agentData)).build();
      }

      return Response.status(400)
          .entity(Map.of("error", "invalid_state", "message", "Unknown status: " + status)).build();
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("host/revoke")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response revokeHost(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      Map<String, Object> hostData = verified.hostData();
      // §5.10 wire shape is the success object {host_id, status:"revoked", agents_revoked:n}.
      // The spec doesn't define a distinct already-revoked error, so treat repeat self-revoke as
      // an idempotent no-op: 200 with agents_revoked:0 (matches the same-shape contract used by
      // revokeAgent above).
      if (hostData != null && "revoked".equals(hostData.get("status"))) {
        return Response
            .ok(Map.of("host_id", iss, "status", "revoked", "agents_revoked", 0))
            .build();
      }

      if (hostData == null) {
        return Response.status(404)
            .entity(Map.of("error", "host_not_found", "message", "Host not found"))
            .build();
      }
      hostData.put("status", "revoked");
      hostData.put("host_id", iss);
      hostData.put("updated_at", nowTimestamp());
      storage().putHost(iss, hostData);

      int agentsRevoked = 0;
      for (Map<String, Object> agentData : storage().findAgentsByHost(iss)) {
        if (!"revoked".equals(agentData.get("status"))) {
          agentData.put("status", "revoked");
          agentData.put("updated_at", nowTimestamp());
          storage().putAgent((String) agentData.get("agent_id"), agentData);
          agentsRevoked++;
        }
      }

      return Response
          .ok(Map.of("host_id", iss, "status", "revoked", "agents_revoked", agentsRevoked))
          .build();

    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("host/rotate-key")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response rotateHostKey(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.forRotateHostKey());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();

      // §5.9 safety: a rotated key (its thumbprint listed in the rotation history) must not be
      // accepted on this endpoint. Otherwise an attacker holding a stale, retired key could try
      // to "rotate" again — even though the legitimate post-rotation iss has already moved on.
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      Map<String, Object> hostData = verified.hostData();
      // Bug 1 fix: rotate-key is a mutation on an existing active host record. Unknown hosts
      // (post-verification with hostData == null) MUST be rejected here, otherwise a self-signed
      // host JWT could materialize a brand-new active host on the server. The dynamic-registration
      // path that creates pending hosts is /agent/register, not this one.
      if (hostData == null) {
        return Response.status(404)
            .entity(Map.of("error", "host_not_found", "message", "Host not found"))
            .build();
      }

      String hostStatus = (String) hostData.get("status");
      if ("revoked".equals(hostStatus)) {
        return Response.status(403)
            .entity(Map.of("error", "host_revoked", "message", "Host already revoked")).build();
      }
      // §5.9 requires the host be active before rotating; pending/rejected hosts have no
      // §2.8-approved owner so a key rotation would silently bypass the approval flow.
      if (!"active".equals(hostStatus)) {
        return Response.status(409)
            .entity(Map.of("error", "invalid_state",
                "message", "Host must be active to rotate the key"))
            .build();
      }

      if (requestBody == null || !requestBody.containsKey("public_key")) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing public_key")).build();
      }

      Object pubKeyObj = requestBody.get("public_key");
      if (!(pubKeyObj instanceof Map)) {
        return Response.status(400)
            .entity(
                Map.of("error", "invalid_request", "message", "public_key must be a JWK object"))
            .build();
      }

      @SuppressWarnings("unchecked")
      Map<String, Object> newHostPublicKeyMap = (Map<String, Object>) pubKeyObj;
      OctetKeyPair newHostKey;
      try {
        newHostKey = OctetKeyPair.parse(newHostPublicKeyMap);
      } catch (Exception e) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Malformed JWK")).build();
      }

      if (!com.nimbusds.jose.jwk.Curve.Ed25519.equals(newHostKey.getCurve())) {
        return Response.status(400)
            .entity(Map.of("error", "unsupported_algorithm", "message",
                "Only Ed25519 keys are supported"))
            .build();
      }

      String newIss = newHostKey.computeThumbprint().toString();
      // When the host was located via the JWKS-URL fallback, the row's PK is the prior thumbprint
      // stored in hostData.host_id, not the JWT's iss. Use the stored PK to record rotation and to
      // remove the old row; otherwise iss already equals the stored PK.
      String oldIss = verified.foundByJwksFallback() && hostData.get("host_id") instanceof String
          ? (String) hostData.get("host_id")
          : iss;
      hostData.put("public_key", newHostPublicKeyMap);
      hostData.put("host_id", newIss);

      storage().recordHostRotation(oldIss, newIss);
      storage().putHost(newIss, hostData);
      storage().removeHost(oldIss);

      for (Map<String, Object> agentData : storage().findAgentsByHost(oldIss)) {
        agentData.put("host_id", newIss);
        storage().putAgent((String) agentData.get("agent_id"), agentData);
      }

      // §5.9 wire shape: rotate-key response is exactly {host_id, status}. The pre-rotation
      // identifier (oldIss) is intentionally omitted from the wire — the rotation history is
      // server-side state surfaced via storage.recordHostRotation, not the public response.
      return Response.ok(Map.of("host_id", newIss, "status", "active")).build();

    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @GET
  @Path("capability/list")
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response listCapabilities(@HeaderParam("Authorization") String authHeader,
      @QueryParam("query") String query,
      @QueryParam("cursor") String cursor,
      @QueryParam("limit") Integer limit) {
    String agentId = null;
    Map<String, Object> verifiedAgentData = null;
    Map<String, Object> verifiedHostData = null;
    boolean isAuthenticated = false;

    // §5.2 catalog auth: route by JWT type to the appropriate full-pipeline verifier. The
    // pre-2026-04 implementation open-coded a signature-only check that ignored aud, iat/exp,
    // jti replay, and host/agent status — making it possible for a self-signed unknown host or
    // expired/replayed token to surface authenticated-visibility caps. The verifiers below
    // enforce the full §4.5 / §4.5.1 pipeline. §5.13: malformed/unsupported-typ Bearers MUST
    // surface 401 invalid_jwt rather than silently downgrading to anonymous public access.
    AuthSniff authType = sniffJwtType(authHeader);
    if (authType == AuthSniff.MALFORMED || authType == AuthSniff.UNSUPPORTED_TYP) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt",
              "message", authType == AuthSniff.MALFORMED
                  ? "Malformed Authorization header"
                  : "JWT must be type host+jwt or agent+jwt"))
          .build();
    }
    if (authType == AuthSniff.HOST_JWT) {
      try {
        HostJwtVerifier.Result verified = hostJwtVerifier()
            .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
        // §4.5.1 / §5.2: a verified host JWT for a known but non-active host MUST be rejected
        // outright — not silently downgraded to anonymous. Only an active host can authenticate
        // to the catalog; an unknown (storedHost=false) or active-but-unlinked host falls back
        // to the public-only catalog read.
        Map<String, Object> hostData = verified.hostData();
        if (verified.storedHost() && hostData != null) {
          String hostStatus = (String) hostData.get("status");
          if ("revoked".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
                .build();
          }
          if ("rejected".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_rejected", "message", "Host is rejected"))
                .build();
          }
          if ("pending".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_pending", "message", "Host is pending"))
                .build();
          }
          if ("active".equals(hostStatus) && hostData.get("user_id") != null) {
            verifiedHostData = hostData;
            isAuthenticated = true;
          }
          // Active-but-unlinked hosts fall through to the public-only catalog read.
        }
      } catch (HostJwtException e) {
        return e.response();
      }
    } else if (authType == AuthSniff.AGENT_JWT) {
      try {
        AgentJwtVerifier.Result verified = agentJwtVerifier().verify(authHeader, issuerUrl());
        agentId = verified.agentId();
        verifiedAgentData = verified.agentData();
        verifiedHostData = verified.hostData();
        isAuthenticated = true;
      } catch (AgentJwtException e) {
        return e.response();
      }
    }

    List<Map<String, Object>> capabilities = new ArrayList<>(
        storage().listCapabilities());
    capabilities.sort(Comparator.comparing(cap -> String.valueOf(cap.get("name"))));

    // Resolve the caller's owning KC user once: agent → agent.user_id, host → host.user_id.
    // Verifier already loaded these maps; reuse them rather than re-reading storage.
    String effectiveUserId = resolveEffectiveUserId(verifiedAgentData, verifiedHostData);

    // Phase 1 of the multi-tenant authz plan: snapshot the caller's KC org memberships
    // and realm-roles for the user-entitlement gate below. May be null when the host or
    // agent isn't yet linked to a KC user (in which case caps with org_id or required_role
    // are invisible — matches the "no entitlements" case).
    UserEntitlement entitlement = loadUserEntitlement(effectiveUserId);

    // §5.2 reconciliation: the listing view is gated solely by the user-entitlement check
    // (Phase 1) — the host's `default_capability_grants` are NOT used as an additional filter
    // here. The defaults are still a meaningful host-scoped concept used by the reactivation
    // flow (`buildReactivationGrants`), but applying them as a list-time narrowing produced a
    // confusing two-layer model: caps were filtered by both "what the user can have" AND "what
    // this host has done before." The spec's §5.2 wording — "capabilities available to the
    // host's linked user" — is the user-entitlement reading; that's what we surface.
    List<Map<String, Object>> visibleCapabilities = new ArrayList<>();
    for (Map<String, Object> cap : capabilities) {
      String visibility = (String) cap.get("visibility");
      if ("public".equals(visibility)) {
        visibleCapabilities.add(cap);
        continue;
      }
      if (!isAuthenticated) {
        continue;
      }
      if (!userEntitlementAllows(cap, entitlement)) {
        continue;
      }
      visibleCapabilities.add(cap);
    }

    // If unauthenticated and no public capabilities are visible, require authentication.
    // §5.2 + §5.14: include the AgentAuth WWW-Authenticate challenge so clients can discover
    // the realm's agent-configuration endpoint and obtain credentials.
    if (!isAuthenticated && visibleCapabilities.isEmpty()) {
      String discoveryUrl = agentConfigurationDiscoveryUrl();
      return Response.status(401)
          .header("WWW-Authenticate", "AgentAuth discovery=\"" + discoveryUrl + "\"")
          .entity(Map.of("error", "authentication_required",
              "message", "Authentication required: no public capabilities available"))
          .build();
    }

    if (query != null && !query.isBlank()) {
      String normalizedQuery = query.toLowerCase(Locale.ROOT);
      visibleCapabilities = visibleCapabilities.stream().filter(cap -> {
        String name = String.valueOf(cap.getOrDefault("name", ""));
        String description = String.valueOf(cap.getOrDefault("description", ""));
        String location = String.valueOf(cap.getOrDefault("location", ""));
        return name.toLowerCase(Locale.ROOT).contains(normalizedQuery)
            || description.toLowerCase(Locale.ROOT).contains(normalizedQuery)
            || location.toLowerCase(Locale.ROOT).contains(normalizedQuery);
      }).toList();
    }

    int startIndex = 0;
    if (cursor != null && !cursor.isBlank()) {
      try {
        String decodedCursor = new String(Base64.getUrlDecoder().decode(cursor),
            StandardCharsets.UTF_8);
        startIndex = Integer.parseInt(decodedCursor);
      } catch (Exception e) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Invalid cursor"))
            .build();
      }
    }

    if (startIndex < 0 || startIndex > visibleCapabilities.size()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Invalid cursor"))
          .build();
    }

    if (limit != null && limit.intValue() < 1) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Invalid limit"))
          .build();
    }

    int endIndex = limit == null
        ? visibleCapabilities.size()
        : Math.min(visibleCapabilities.size(), startIndex + limit.intValue());
    List<Map<String, Object>> page = new ArrayList<>(visibleCapabilities.subList(startIndex,
        endIndex));

    boolean hasMore = endIndex < visibleCapabilities.size();
    String nextCursor = hasMore
        ? Base64.getUrlEncoder().withoutPadding()
            .encodeToString(String.valueOf(endIndex).getBytes(StandardCharsets.UTF_8))
        : null;

    List<Map<String, Object>> responseCapabilities = new ArrayList<>();
    for (Map<String, Object> cap : page) {
      Map<String, Object> capInfo = new HashMap<>();
      capInfo.put("name", cap.get("name"));
      capInfo.put("description", cap.get("description"));
      if (agentId != null) {
        capInfo.put("grant_status", computeGrantStatus(agentId, (String) cap.get("name")));
      }
      responseCapabilities.add(capInfo);
    }

    Map<String, Object> response = new HashMap<>();
    response.put("capabilities", responseCapabilities);
    response.put("has_more", hasMore);
    response.put("next_cursor", nextCursor);
    // §10.6: catalog responses SHOULD be cacheable; 5 minutes is the recommended max-age. Use
    // private for authenticated callers (per-user view) and public for the unauthenticated
    // public-only catalog view.
    String cacheControl = isAuthenticated ? "private, max-age=300" : "public, max-age=300";
    return Response.ok(response).header("Cache-Control", cacheControl).build();
  }

  @GET
  @Path("capability/describe")
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response describeCapability(
      @HeaderParam("Authorization") String authHeader,
      @QueryParam("name") String name) {

    if (name == null || name.isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing name parameter"))
          .build();
    }

    Map<String, Object> cap = storage().getCapability(name);
    if (cap == null) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }

    String agentId = null;
    Map<String, Object> verifiedAgentData = null;
    Map<String, Object> verifiedHostData = null;
    boolean isAuthenticated = false;

    // §5.2.1 catalog auth: same routing as listCapabilities — full §4.5 verification via the
    // typed verifiers. §5.13: malformed/unsupported-typ Bearers MUST surface 401 invalid_jwt
    // rather than silently downgrading to anonymous; a known non-active host MUST be rejected
    // outright rather than downgraded.
    AuthSniff authType = sniffJwtType(authHeader);
    if (authType == AuthSniff.MALFORMED || authType == AuthSniff.UNSUPPORTED_TYP) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt",
              "message", authType == AuthSniff.MALFORMED
                  ? "Malformed Authorization header"
                  : "JWT must be type host+jwt or agent+jwt"))
          .build();
    }
    if (authType == AuthSniff.HOST_JWT) {
      try {
        HostJwtVerifier.Result verified = hostJwtVerifier()
            .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
        Map<String, Object> hostData = verified.hostData();
        if (verified.storedHost() && hostData != null) {
          String hostStatus = (String) hostData.get("status");
          if ("revoked".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
                .build();
          }
          if ("rejected".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_rejected", "message", "Host is rejected"))
                .build();
          }
          if ("pending".equals(hostStatus)) {
            return Response.status(403)
                .entity(Map.of("error", "host_pending", "message", "Host is pending"))
                .build();
          }
          if ("active".equals(hostStatus) && hostData.get("user_id") != null) {
            verifiedHostData = hostData;
            isAuthenticated = true;
          }
          // Active-but-unlinked hosts fall through to the public-only catalog read.
        }
      } catch (HostJwtException e) {
        return e.response();
      }
    } else if (authType == AuthSniff.AGENT_JWT) {
      try {
        AgentJwtVerifier.Result verified = agentJwtVerifier().verify(authHeader, issuerUrl());
        agentId = verified.agentId();
        verifiedAgentData = verified.agentData();
        verifiedHostData = verified.hostData();
        isAuthenticated = true;
      } catch (AgentJwtException e) {
        return e.response();
      }
    }

    // For unauthenticated callers, non-public capabilities must be indistinguishable from
    // missing ones — returning 403 confirms the cap exists and leaks the catalog. Mirror the
    // entitlement-gate path below and respond 404 capability_not_found instead.
    if (!"public".equals(cap.get("visibility")) && !isAuthenticated) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }

    // Phase 1 user-entitlement gate: org/role gates apply only to authenticated-visibility
    // caps for authenticated callers. Public caps bypass entirely (anonymous can see them).
    // Failed gate returns 404 capability_not_found to avoid leaking the cap's existence.
    if (isAuthenticated && "authenticated".equals(cap.get("visibility"))) {
      String effectiveUserId = resolveEffectiveUserId(verifiedAgentData, verifiedHostData);
      UserEntitlement entitlement = loadUserEntitlement(effectiveUserId);
      if (!userEntitlementAllows(cap, entitlement)) {
        return Response.status(404)
            .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
            .build();
      }
    }

    Map<String, Object> result = new HashMap<>(cap);
    if (agentId != null) {
      result.put("grant_status", computeGrantStatus(agentId, name));
    }

    // §10.6: cache the describe response for 5 minutes; private when the response was tailored
    // to an authenticated principal, public otherwise.
    String cacheControl = isAuthenticated ? "private, max-age=300" : "public, max-age=300";
    return Response.ok(result).header("Cache-Control", cacheControl).build();
  }

  @POST
  @Path("agent/request-capability")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response requestCapability(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    // §4.5 + §4.6: full agent-JWT pipeline via the centralized verifier. Pre-2026-04 this
    // endpoint open-coded its own checks that consumed `jti` before signature verification and
    // looked up the host directly by JWT `iss` with no JWKS-rotation fallback. The verifier now
    // enforces typ=agent+jwt, claims/timestamps, aud, iss-vs-host binding (with JWKS fallback for
    // rotation-capable hosts), agent and host status (with §§2.3-2.5 lifecycle clocks),
    // signature-then-replay ordering. Non-active agents and non-active hosts surface as
    // 401 invalid_jwt — same convention as catalog endpoints.
    AgentJwtVerifier.Result verified;
    try {
      verified = agentJwtVerifier().verify(authHeader, issuerUrl());
    } catch (AgentJwtException e) {
      return e.response();
    }

    try {
      String agentId = verified.agentId();
      String hostId = verified.hostId();
      Map<String, Object> agentData = verified.agentData();
      Map<String, Object> hostData = verified.hostData();

      if (requestBody == null || !requestBody.containsKey("capabilities")) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing capabilities"))
            .build();
      }

      Object rawRequestedCaps = requestBody.get("capabilities");
      if (!(rawRequestedCaps instanceof List<?>)) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "capabilities must be an array"))
            .build();
      }
      List<?> requestedCaps = (List<?>) rawRequestedCaps;
      if (requestedCaps.isEmpty()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Capabilities must be non-empty"))
            .build();
      }

      List<Map<String, Object>> existingGrants = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      List<Map<String, Object>> newGrants = new ArrayList<>();
      List<String> invalidCaps = new ArrayList<>();
      boolean requiresApproval = false;
      int alreadyActiveCount = 0;

      // §5.3 / §3.1: per-host TOFU defaults. Mirror registerAgent's path so a cap already in the
      // host's `default_capabilities` auto-grants here too — without this, /agent/register and
      // /agent/request-capability return inconsistent statuses (active vs. pending) for the same
      // agent + same cap when the host has previously approved that cap.
      List<String> hostDefaults = hostDefaultCapabilities(hostData);

      // Phase 1 entitlement gate at request-capability: block scoped caps the agent's effective
      // user can't satisfy. Mirrors the gate added at /agent/register; closes the same gap on
      // post-registration cap requests.
      String requestCapMode = (String) agentData.get("mode");
      String requestCapHostOwner = (String) hostData.get("user_id");
      boolean shouldRunRequestGate = "autonomous".equals(requestCapMode)
          || (requestCapHostOwner != null && !requestCapHostOwner.isBlank());
      UserEntitlement requestCapEntitlement = shouldRunRequestGate
          ? loadUserEntitlement(resolveEffectiveUserId(agentData, hostData))
          : null;

      for (Object capObj : requestedCaps) {
        String capName;
        Map<String, Object> requestedConstraints = null;
        if (capObj instanceof String) {
          capName = (String) capObj;
        } else if (capObj instanceof Map) {
          Map<?, ?> capMap = (Map<?, ?>) capObj;
          Object rawCapName = capMap.get("name");
          if (!(rawCapName instanceof String) || ((String) rawCapName).isBlank()) {
            return Response.status(400)
                .entity(Map.of("error", "invalid_request",
                    "message", "Capability object must include a non-empty name"))
                .build();
          }
          capName = (String) rawCapName;
          Object rawConstraints = capMap.get("constraints");
          if (rawConstraints != null) {
            if (!(rawConstraints instanceof Map)) {
              return Response.status(400)
                  .entity(Map.of("error", "invalid_request",
                      "message", "constraints must be an object"))
                  .build();
            }
            requestedConstraints = (Map<String, Object>) rawConstraints;
          }
        } else {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request",
                  "message", "Each capability must be a string or object"))
              .build();
        }

        if (capName.isBlank()) {
          return Response.status(400)
              .entity(Map.of("error", "invalid_request", "message", "Capability name is empty"))
              .build();
        }

        Map<String, Object> registeredCap = storage().getCapability(capName);
        if (registeredCap == null) {
          invalidCaps.add(capName);
          continue;
        }

        if (shouldRunRequestGate
            && !userEntitlementAllows(registeredCap, requestCapEntitlement)) {
          invalidCaps.add(capName);
          continue;
        }

        List<String> unknownOperators = unknownConstraintOperators(requestedConstraints);
        if (!unknownOperators.isEmpty()) {
          return unknownConstraintOperatorResponse(unknownOperators);
        }

        if (existingGrants != null) {
          boolean alreadyGranted = false;
          Map<String, Object> existingActiveGrant = null;
          for (Map<String, Object> g : existingGrants) {
            if (capName.equals(g.get("capability")) && "active".equals(g.get("status"))) {
              alreadyGranted = true;
              existingActiveGrant = g;
              break;
            }
          }
          if (alreadyGranted) {
            alreadyActiveCount++;
            newGrants.add(existingActiveGrant); // include existing active grant in response
            continue; // don't re-process
          }
        }

        boolean capReqApproval = Boolean.TRUE.equals(registeredCap.get("requires_approval"));
        boolean autoDeny = Boolean.TRUE.equals(registeredCap.get("auto_deny"));
        // §5.3: TOFU auto-grant — a cap that's already in the host's defaults auto-approves
        // even if the cap registry says requires_approval=true, because the linked user has
        // approved it for this host before. Without this, /agent/request-capability returns
        // pending for caps that /agent/register would auto-grant under the same host — a
        // semantic inconsistency between the two endpoints for the same (agent, cap) pair.
        boolean inHostDefaults = hostDefaults.contains(capName);
        boolean needsApproval = capReqApproval && !inHostDefaults;
        if (needsApproval && !autoDeny)
          requiresApproval = true;

        Map<String, Object> grant = new HashMap<>();
        grant.put("capability", capName);
        if (autoDeny) {
          grant.put("status", "denied");
          grant.put("reason", "Capability has auto_deny enabled");
        } else if (needsApproval) {
          grant.put("status", "pending");
          // §5.4: pending grants on the wire are compact {capability, status} — the per-grant
          // status URL is exposed only via the documented extension endpoint, not on the grant.
          // §2.13: stash the requested scope so the approval can promote it into `constraints`
          // without re-asking. Mirrors the pending-grant path in registerAgent. The pending
          // response stays compact (§5.4) — sanitizeAgentResponse strips this key on the way out.
          if (requestedConstraints != null) {
            grant.put("requested_constraints", requestedConstraints);
          }
        } else {
          grant.put("status", "active");
          grant.put("description", registeredCap.get("description"));
          if (registeredCap.containsKey("input")) {
            grant.put("input", registeredCap.get("input"));
          }
          if (registeredCap.containsKey("output")) {
            grant.put("output", registeredCap.get("output"));
          }
          grant.put("granted_by", hostId);
          if (requestedConstraints != null) {
            grant.put("constraints", requestedConstraints);
          }
        }
        if (requestBody.containsKey("reason")) {
          grant.put("reason", requestBody.get("reason"));
        }
        newGrants.add(grant);
      }

      if (!invalidCaps.isEmpty()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_capabilities", "message", "Invalid capabilities",
                "invalid_capabilities", invalidCaps))
            .build();
      }

      // If all requested capabilities were already active, return 409
      if (alreadyActiveCount == requestedCaps.size()) {
        return Response.status(409)
            .entity(Map.of("error", "already_granted", "message",
                "All capabilities are already granted"))
            .build();
      }

      // Add only truly new grants (those not already active) to the agent's grant list
      List<Map<String, Object>> trulyNewGrants = new ArrayList<>();
      for (Map<String, Object> g : newGrants) {
        if (existingGrants == null || !existingGrants.contains(g)) {
          trulyNewGrants.add(g);
        }
      }
      if (existingGrants != null) {
        existingGrants.addAll(trulyNewGrants);
      } else {
        agentData.put("agent_capability_grants", new ArrayList<>(newGrants));
      }

      Map<String, Object> responseMap = new HashMap<>();
      responseMap.put("agent_id", agentId);
      // §5.4: pending grants are returned in compact shape — sanitize strips the internal
      // `requested_constraints` stash from any pending entry so storage retains scope while
      // the wire payload stays compact.
      responseMap.put("agent_capability_grants", sanitizeGrantsForResponse(newGrants));
      if (requiresApproval) {
        Map<String, Object> hostDataForApproval = storage().getHost(hostId);
        String bindingMessage = requestBody.get("binding_message") instanceof String bm
            ? bm
            : null;
        // §5.4 + §7.1 expiry persistence: persist the approval blob on the agent so verifyApprove
        // can enforce `issued_at_ms` against the same window we advertise here. Without this,
        // capability-request approvals were redeemable indefinitely past `expires_in` because
        // /verify/approve reads `agentData.approval.issued_at_ms` and that key was never stored.
        // Concurrent-approval safety: if the agent already has a pending approval blob (e.g. a
        // registration that hasn't been resolved yet), reuse it — the user's single approve action
        // covers all pending grants together, and stamping a fresh `issued_at_ms` would extend the
        // existing approval's window beyond what was originally advertised.
        Object existingApproval = agentData.get("approval");
        Map<String, Object> selectedApproval;
        if (existingApproval instanceof Map<?, ?>) {
          @SuppressWarnings("unchecked")
          Map<String, Object> reused = (Map<String, Object>) existingApproval;
          selectedApproval = reused;
        } else {
          selectedApproval = selectApprovalObject(agentId, agentData,
              hostDataForApproval, (String) agentData.get("mode"), bindingMessage);
          agentData.put("approval", selectedApproval);
        }
        responseMap.put("approval", selectedApproval);
      }
      agentData.put("updated_at", nowTimestamp());
      agentData.put("expires_at", futureTimestamp(DEFAULT_AGENT_TTL_SECONDS));
      storage().putAgent(agentId, agentData);

      return Response.ok(responseMap).build();

    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  @POST
  @Path("capability/execute")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response executeCapability(
      @HeaderParam("Authorization") String authHeader,
      Map<String, Object> requestBody) {

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      String discoveryUrl = agentConfigurationDiscoveryUrl();
      return Response.status(401)
          .header("WWW-Authenticate", "AgentAuth discovery=\"" + discoveryUrl + "\"")
          .entity(Map.of("error", "authentication_required",
              "message", "Missing or invalid Authorization header"))
          .build();
    }

    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(authHeader.substring(7));
    } catch (Exception e) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt", "message", "Malformed JWT"))
          .build();
    }

    String jwtType = jwt.getHeader().getType() != null ? jwt.getHeader().getType().getType() : null;
    if (!"agent+jwt".equals(jwtType)) {
      return Response.status(401)
          .entity(Map.of("error", "invalid_jwt", "message", "JWT must be type agent+jwt"))
          .build();
    }

    try {
      if (jwt.getJWTClaimsSet().getExpirationTime() == null
          || jwt.getJWTClaimsSet().getIssueTime() == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Missing timestamps"))
            .build();
      }

      long now = System.currentTimeMillis();
      if (jwt.getJWTClaimsSet().getIssueTime().getTime() > now + CLOCK_SKEW_MS) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "JWT issued in the future"))
            .build();
      }

      if (now > jwt.getJWTClaimsSet().getExpirationTime().getTime()) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Token expired"))
            .build();
      }

      String jti = jwt.getJWTClaimsSet().getJWTID();
      if (jti == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Missing jti"))
            .build();
      }

      String agentId = jwt.getJWTClaimsSet().getSubject();
      if (agentId == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Missing sub"))
            .build();
      }

      String hostId = jwt.getJWTClaimsSet().getIssuer();
      if (hostId == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Missing iss"))
            .build();
      }

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Agent not found"))
            .build();
      }

      // Audit E-F6 (deferred): exact-match `iss == agent.host_id` is correct for inline-key hosts
      // but does not honour the JWKS host-rotation fallback that {@link AgentJwtVerifier#verify}
      // applies in Wave 1 (rebinds the verified iss to the rotated host's id). Migrating
      // /capability/execute to {@code agentJwtVerifier().verify(...)} requires reshaping the
      // upstream-proxy + constraint-validator integration; deferred to a follow-up.
      if (!hostId.equals(agentData.get("host_id"))) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host mismatch"))
            .build();
      }

      Map<String, Object> hostData = storage().getHost(hostId);
      if (hostData == null) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host not found"))
            .build();
      }
      // Audit E-F3 / §§2.11, 4.5: pre-fix only blocked `revoked`/`pending`. `rejected` (and any
      // other non-active terminal/transition state) used to slip through. The shared guard now
      // returns the appropriate 403 (host_revoked / host_pending / host_rejected / unauthorized).
      Response hostStateRejection = hostMustBeActive(hostData);
      if (hostStateRejection != null) {
        return hostStateRejection;
      }

      Map<String, Object> agentPublicKeyMap = resolveAgentPublicKeyMap(agentData, jwt);
      OctetKeyPair agentKey = OctetKeyPair.parse(agentPublicKeyMap);
      JWSVerifier verifier = new Ed25519Verifier(agentKey);
      if (!jwt.verify(verifier)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Invalid signature"))
            .build();
      }

      // §4.5 + §4.6: jti replay detection MUST run AFTER signature verification and identity/
      // state validation. Otherwise an unsigned/forged token with a guessed jti could burn
      // that jti before the legitimate signed token is processed, denying the legitimate
      // agent its single-use credential.
      if (isJtiReplay(jwt, jti)) {
        return Response.status(401)
            .entity(Map.of("error", "jti_replay", "message", "Replay detected"))
            .build();
      }

      // §§2.3-2.5: lazily evaluate lifecycle clocks before honouring the request. A token may
      // arrive while the stored status still says `active`; the centralised evaluator catches
      // sessions/max/absolute lifetimes elapsing between writes. Persist transitions so other
      // flows see the new status.
      String statusBeforeExecuteClock = (String) agentData.get("status");
      LifecycleClock.Result executeClock = LifecycleClock.applyExpiry(agentData);
      if (executeClock != LifecycleClock.Result.ACTIVE
          && !java.util.Objects.equals(statusBeforeExecuteClock, agentData.get("status"))) {
        agentData.put("updated_at", nowTimestamp());
        storage().putAgent(agentId, agentData);
      }

      String status = (String) agentData.get("status");
      if ("revoked".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_revoked", "message", "Agent is revoked"))
            .build();
      }
      if ("pending".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_pending", "message", "Agent is pending"))
            .build();
      }
      if ("expired".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_expired", "message", "Agent is expired"))
            .build();
      }
      if ("rejected".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_rejected", "message", "Agent is rejected"))
            .build();
      }
      if ("claimed".equals(status)) {
        return Response.status(403)
            .entity(Map.of("error", "agent_claimed", "message", "Agent is claimed"))
            .build();
      }

      if (requestBody == null
          || (!requestBody.containsKey("capability") && !requestBody.containsKey("name"))) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Missing capability field"))
            .build();
      }

      Object rawCapabilityName = requestBody.get("capability");
      if (rawCapabilityName == null) {
        rawCapabilityName = requestBody.get("name"); // fallback alias
      }
      if (!(rawCapabilityName instanceof String)) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "capability must be a string"))
            .build();
      }
      String capabilityName = (String) rawCapabilityName;
      if (capabilityName == null || capabilityName.isBlank()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "Empty capability name"))
            .build();
      }

      Object restrictedCapabilities = jwt.getJWTClaimsSet().getClaim("capabilities");
      if (restrictedCapabilities != null
          && (!(restrictedCapabilities instanceof List<?> restrictedList)
              || !restrictedList.contains(capabilityName))) {
        return Response.status(403)
            .entity(Map.of("error", "capability_not_granted",
                "message", "JWT is not scoped for this capability"))
            .build();
      }

      Object rawArguments = requestBody.get("arguments");
      if (rawArguments != null && !(rawArguments instanceof Map)) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request", "message", "arguments must be an object"))
            .build();
      }

      List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      Map<String, Object> activeGrant = null;
      // Audit E-F4 / §3.3: effective grants must be active AND not past expires_at.
      Instant executeGrantNow = Instant.now();
      if (grants != null) {
        for (Map<String, Object> g : grants) {
          if (capabilityName.equals(g.get("capability"))
              && isEffectiveActiveGrant(g, executeGrantNow)) {
            activeGrant = g;
            break;
          }
        }
      }

      Map<String, Object> registeredCap = storage().getCapability(capabilityName);
      if (registeredCap == null && activeGrant != null) {
        return Response.status(403)
            .entity(Map.of("error", "capability_not_granted",
                "message", "Capability has been removed"))
            .build();
      }
      if (registeredCap == null) {
        return Response.status(404)
            .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
            .build();
      }
      if (activeGrant == null) {
        return Response.status(403)
            .entity(Map.of("error", "capability_not_granted",
                "message", "Agent does not hold an active grant for this capability"))
            .build();
      }

      // §4.3: agent+jwt aud MUST be the resolved location URL — `cap.location` if set, else
      // `default_location` (which our discovery advertises as `<issuer>/capability/execute`).
      // The gateway accepts the token because the resolved URL identifies the cap as the
      // intended recipient; we proxy on its behalf, but the aud belongs to the cap.
      String defaultLocation = issuerUrl() + "/capability/execute";
      String capLocation = (String) registeredCap.get("location");
      String resolvedLocation = (capLocation != null && !capLocation.isBlank())
          ? capLocation
          : defaultLocation;
      List<String> aud = jwt.getJWTClaimsSet().getAudience();
      if (aud == null || !aud.contains(resolvedLocation)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Invalid audience"))
            .build();
      }

      // Phase 2 lazy entitlement re-eval at execute (gateway mode). Mirrors the introspect
      // re-eval in direct mode: a grant that was active at register/approve time may no longer
      // satisfy the current org/role gate (e.g. role removed without firing the eager
      // org-leave cascade). Strip stale grants here so gateway-mode flows fail closed.
      UserEntitlement executeEntitlement = loadUserEntitlement(
          resolveEffectiveUserId(agentData, hostData));
      if (!userEntitlementAllows(registeredCap, executeEntitlement)) {
        return Response.status(403)
            .entity(Map.of("error", "insufficient_authority",
                "message",
                "Agent's owner no longer satisfies the capability's org/role gate"))
            .build();
      }

      Map<String, Object> constraints = (Map<String, Object>) activeGrant.get("constraints");
      if (constraints != null) {
        Map<String, Object> arguments = (Map<String, Object>) requestBody.get("arguments");
        List<ConstraintViolation> violations;
        try {
          violations = new ConstraintValidator().validate(constraints, arguments);
        } catch (IllegalArgumentException e) {
          return unknownConstraintOperatorResponse(List.of(e.getMessage()
              .replace("Unknown constraint operator: ", "")));
        }
        if (!violations.isEmpty()) {
          List<Map<String, Object>> violationMaps = new ArrayList<>();
          for (ConstraintViolation v : violations) {
            Map<String, Object> vmap = new HashMap<>();
            vmap.put("field", v.field());
            vmap.put("constraint", v.constraint());
            vmap.put("actual", v.actual());
            violationMaps.add(vmap);
          }
          Map<String, Object> errorResponse = new HashMap<>();
          errorResponse.put("error", "constraint_violated");
          errorResponse.put("message", "One or more constraints were violated");
          errorResponse.put("violations", violationMaps);
          return Response.status(403).entity(errorResponse).build();
        }
      }

      agentData.put("last_used_at", nowTimestamp());
      agentData.put("expires_at", futureTimestamp(DEFAULT_AGENT_TTL_SECONDS));
      storage().putAgent(agentId, agentData);

      String location = (String) registeredCap.get("location");
      if (location == null || location.isBlank()) {
        return Response.status(500).entity(Map.of("error", "capability_misconfigured",
            "message",
            "Capability has no location and this server does not execute capabilities directly. "
                + "Register the capability with an explicit location pointing at a resource server."))
            .build();
      }
      String bodyJson = JsonSerialization.writeValueAsString(requestBody);

      URI originalUri = URI.create(location);
      List<URI> upstreamCandidates = upstreamCandidateUris(originalUri);
      Exception lastConnectionFailure = null;

      for (URI upstreamUri : upstreamCandidates) {
        try {
          System.err.println("[agent-auth] Proxying to: " + upstreamUri);
          URL url = upstreamUri.toURL();
          HttpURLConnection conn = (HttpURLConnection) url.openConnection();
          conn.setRequestMethod("POST");
          conn.setDoOutput(true);
          conn.setRequestProperty("Content-Type", "application/json");
          // Tell upstream we accept SSE in addition to JSON. Without this header some upstreams
          // refuse to upgrade their response to text/event-stream.
          conn.setRequestProperty("Accept", "text/event-stream, application/json;q=0.9, */*;q=0.5");
          conn.setConnectTimeout(10_000);
          // Default read timeout for sync JSON responses. SSE detection below disables it before
          // we hand off the InputStream to a StreamingOutput.
          conn.setReadTimeout(30_000);

          try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyJson.getBytes(StandardCharsets.UTF_8));
          }

          int upstreamStatus = conn.getResponseCode();
          String upstreamContentType = conn.getContentType() != null
              ? conn.getContentType()
              : "application/json";
          // Audit E-F2 / spec §5.4 streaming: pre-fix used `readAllBytes()`, which buffered the
          // entire SSE response until the upstream closed (or 30s read-timeout fired). Detect
          // text/event-stream (case-insensitive, including parameters like "; charset=utf-8") and
          // chunked transfer-encoding, and stream those responses through a JAX-RS
          // StreamingOutput. Sync JSON keeps the buffered path so existing 200 / 4xx / 5xx
          // behaviour is untouched.
          String contentTypeLower = upstreamContentType.toLowerCase(Locale.ROOT);
          String transferEncoding = conn.getHeaderField("Transfer-Encoding");
          boolean isSse = contentTypeLower.startsWith("text/event-stream");
          boolean isChunked = transferEncoding != null
              && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked");
          boolean shouldStream = isSse || isChunked;

          if (shouldStream) {
            // Disable the read timeout for streaming bodies — SSE event spacing can legitimately
            // exceed 30s. The upstream/network closing the socket is the termination signal.
            conn.setReadTimeout(0);
            final InputStream upstreamStream = upstreamStatus >= 400
                ? conn.getErrorStream()
                : conn.getInputStream();
            final String cacheControl = conn.getHeaderField("Cache-Control");
            final String retryAfter = conn.getHeaderField("Retry-After");
            StreamingOutput streamingBody = new StreamingOutput() {
              @Override
              public void write(OutputStream output) throws IOException {
                if (upstreamStream == null) {
                  return;
                }
                try (InputStream in = upstreamStream) {
                  // 1 KiB buffer keeps SSE event delivery low-latency; flush after every read so
                  // the client receives events as the upstream emits them.
                  byte[] buffer = new byte[1024];
                  int read;
                  while ((read = in.read(buffer)) != -1) {
                    if (read > 0) {
                      output.write(buffer, 0, read);
                      output.flush();
                    }
                  }
                }
              }
            };
            Response.ResponseBuilder builder = Response.status(upstreamStatus)
                .entity(streamingBody)
                .type(upstreamContentType);
            if (cacheControl != null) {
              builder.header("Cache-Control", cacheControl);
            } else if (isSse) {
              // SSE clients expect responses to bypass intermediary caches.
              builder.header("Cache-Control", "no-cache");
            }
            if (retryAfter != null) {
              builder.header("Retry-After", retryAfter);
            }
            return builder.build();
          }

          InputStream is = upstreamStatus >= 400 ? conn.getErrorStream() : conn.getInputStream();
          byte[] responseBytes = is != null ? is.readAllBytes() : new byte[0];

          return Response.status(upstreamStatus)
              .entity(responseBytes)
              .type(upstreamContentType)
              .build();
        } catch (java.net.ConnectException | java.net.NoRouteToHostException
            | java.net.UnknownHostException e) {
          lastConnectionFailure = e;
        }
      }

      if (lastConnectionFailure != null) {
        String msg = lastConnectionFailure.getClass().getName() + ": "
            + lastConnectionFailure.getMessage();
        return Response.status(500)
            .entity(Map.of("error", "internal_error", "message", msg))
            .build();
      }

      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", "Unable to reach upstream"))
          .build();

    } catch (Exception e) {
      String msg = e.getClass().getName() + ": " + e.getMessage();
      // Print stack trace to help debug
      e.printStackTrace(System.err);
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", msg))
          .build();
    }
  }

  @GET
  @Path("agent/{agentId}/capabilities/{capabilityName}/status")
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response getCapabilityGrantStatus(
      @HeaderParam("Authorization") String authHeader,
      @PathParam("agentId") String agentId,
      @PathParam("capabilityName") String capabilityName) {
    // §5.5 polling semantics: the per-grant status URL is published into the registration response
    // for pending grants. Pending agents cannot mint a valid agent+jwt (§2.3), so the host — the
    // owner that registered the agent — is the principal that polls this endpoint. Auth therefore
    // matches the §4.5.1 host-JWT pipeline used by the lifecycle endpoints. After the host JWT is
    // verified we look up the agent and confirm it belongs to the host (`agentData.host_id` ==
    // verified `iss`, which the verifier rebinds for JWKS-fallback hosts).
    HostJwtVerifier.Result verified;
    try {
      verified = hostJwtVerifier()
          .verify(authHeader, issuerUrl(), HostJwtVerifier.Options.defaults());
    } catch (HostJwtException e) {
      return e.response();
    }

    try {
      String iss = verified.iss();
      if (storage().isHostRotated(iss)) {
        return Response.status(401)
            .entity(Map.of("error", "invalid_jwt", "message", "Host key has been rotated"))
            .build();
      }

      Map<String, Object> agentData = storage().getAgent(agentId);
      if (agentData == null) {
        return Response.status(404)
            .entity(Map.of("error", "agent_not_found", "message", "Agent not found"))
            .build();
      }

      if (!iss.equals(agentData.get("host_id"))) {
        return Response.status(403)
            .entity(Map.of("error", "unauthorized", "message", "Host mismatch"))
            .build();
      }

      List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      if (grants != null) {
        for (Map<String, Object> grant : grants) {
          if (capabilityName.equals(grant.get("capability"))) {
            Map<String, Object> response = new HashMap<>();
            response.put("agent_id", agentId);
            response.put("capability", capabilityName);
            response.put("status", grant.get("status"));
            if (grant.containsKey("reason")) {
              response.put("reason", grant.get("reason"));
            }
            return Response.ok(response).build();
          }
        }
      }
      return Response.status(404)
          .entity(Map.of("error", "capability_not_granted", "message", "Grant not found"))
          .build();
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "internal_error", "message", e.getMessage()))
          .build();
    }
  }

  /**
   * AAP §5.3 / §7.1 HTML verification page. Browser-facing landing URL published as
   * {@code verification_uri} in the approval object. Renders minimal inline HTML (no FreeMarker
   * theme yet) showing the {@code user_code} and an approval form.
   */
  @GET
  @Path("verify")
  @Produces(MediaType.TEXT_HTML)
  public Response verifyPage(
      @QueryParam("user_code") String userCode,
      @QueryParam("agent_id") String agentId,
      @HeaderParam("Accept") String acceptHeader) {
    // §8.11 + §7.1 browser flow: when the request looks like a browser navigation (Accept
    // includes text/html) and there is no fresh KC identity cookie, bounce through the realm's
    // standard login flow so the user authenticates first. The redirect comes back here with
    // the cookie set, at which point we render the approval form.
    if (acceptsHtml(acceptHeader) && !hasKeycloakIdentityCookie()) {
      return Response.temporaryRedirect(buildLoginRedirectUri(userCode, agentId)).build();
    }
    String normalized = normalizeUserCode(userCode);
    // Audit B-P1b: CIBA email deep links carry agent_id (no user_code) — look up the pending
    // agent by id when user_code is absent. transitionPendingAgent already supports the
    // agent_id path; verifyPage just needs to plumb it through the rendered form so the POST
    // submission preserves it.
    boolean usingAgentId = (normalized == null || normalized.isBlank())
        && agentId != null && !agentId.isBlank();
    Map<String, Object> pendingAgent;
    if (normalized != null && !normalized.isBlank()) {
      pendingAgent = storage().findAgentByUserCode(normalized);
    } else if (usingAgentId) {
      pendingAgent = storage().getAgent(agentId);
      // Only render the agent_id approval surface for agents that are actually pending — either
      // the agent itself is pending or it has at least one pending grant. Anything else is
      // either a closed approval or an unrelated agent the caller shouldn't see by id.
      if (pendingAgent != null) {
        String agentStatus = (String) pendingAgent.get("status");
        if (!"pending".equals(agentStatus) && !hasPendingGrants(pendingAgent)) {
          pendingAgent = null;
        }
      }
    } else {
      pendingAgent = null;
    }
    String name = pendingAgent == null ? null : (String) pendingAgent.get("name");
    String hostId = pendingAgent == null ? null : (String) pendingAgent.get("host_id");
    String status = pendingAgent == null ? null : (String) pendingAgent.get("status");

    // §8.11 defense-in-depth: mint a CSRF token bound to this GET. The POST handler enforces
    // double-submit: the cookie value MUST match the hidden form field. Bearer-authenticated
    // POSTs skip this check (they already carry proof of intent).
    String csrfToken = generateCsrfToken();

    StringBuilder html = new StringBuilder();
    html.append("<!DOCTYPE html>\n")
        .append("<html lang=\"en\">\n")
        .append("<head>\n")
        .append("<meta charset=\"utf-8\">\n")
        .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
        .append("<title>Agent Auth — Approve registration</title>\n")
        .append("</head>\n")
        .append("<body>\n")
        .append("<main>\n")
        .append("<h1>Agent Auth — Approve registration</h1>\n");

    if ((normalized == null || normalized.isBlank()) && !usingAgentId) {
      html.append("<p>Enter the user code your agent gave you.</p>\n")
          .append("<form method=\"get\" action=\"verify\" role=\"search\"\n")
          .append("      aria-label=\"Look up user code\">\n")
          .append("<p>\n")
          .append("<label for=\"user_code\">User code</label>\n")
          .append("<input type=\"text\" id=\"user_code\" name=\"user_code\"\n")
          .append("       autocomplete=\"one-time-code\" required autofocus\n")
          .append("       aria-describedby=\"user_code_hint\"\n")
          .append("       pattern=\"[A-Za-z0-9-]{8,9}\" minlength=\"8\" maxlength=\"9\">\n")
          .append("<span id=\"user_code_hint\">Eight letters, e.g. ABCD-EFGH.</span>\n")
          .append("</p>\n")
          .append("<p><button type=\"submit\">Look up</button></p>\n")
          .append("</form>\n");
    } else if (pendingAgent == null) {
      // Audit B-P1b: a missing pending agent on the agent_id path means the link is stale or
      // the agent is no longer pending. Use a generic message rather than echoing the agent_id.
      String detail = usingAgentId
          ? "No pending approval matches that link. It may have expired or already been used."
          : "No pending approval found for code <code>"
              + htmlEscape(displayUserCode(normalized)) + "</code>.\n"
              + "It may have expired or already been used.";
      html.append("<section role=\"alert\" aria-live=\"polite\">\n")
          .append("<h2>Unknown or expired approval</h2>\n")
          .append("<p>").append(detail).append("</p>\n")
          .append("</section>\n");
    } else if ("rejected".equals(status) || "revoked".equals(status)
        || "claimed".equals(status)) {
      html.append("<section role=\"alert\" aria-live=\"polite\">\n")
          .append("<h2>Approval already closed</h2>\n")
          .append("<p>This approval is no longer pending. The agent's current status is\n")
          .append("<code>").append(htmlEscape(status)).append("</code>. ")
          .append("Your agent must start a new flow.</p>\n")
          .append("</section>\n");
    } else {
      // Audit B-P2: present the requested capability detail so the approver knows what they're
      // authorizing. The verifyPage previously showed only host+agent name; spec §5.3 / §8.10
      // require capability names + descriptions + constraints, plus reason / host_name /
      // binding_message when present.
      html.append("<section aria-labelledby=\"request-summary\">\n")
          .append("<h2 id=\"request-summary\">Registration request</h2>\n")
          .append("<p>Host <code>")
          .append(htmlEscape(hostId == null ? "unknown" : hostId))
          .append("</code> is requesting to register an agent named\n<strong>")
          .append(htmlEscape(name == null ? "(unnamed)" : name))
          .append("</strong>. See ")
          .append("<a href=\"https://www.rfc-editor.org/rfc/rfc8628\" rel=\"noreferrer\">\n")
          .append("RFC 8628</a> for the flow this implements.</p>\n");
      appendApprovalContext(html, pendingAgent, hostId);
      appendPendingGrants(html, pendingAgent);
      html.append("</section>\n");
      html.append("<form method=\"post\" action=\"verify\"\n")
          .append("      aria-label=\"Approve or deny agent registration\">\n");
      if (normalized != null && !normalized.isBlank()) {
        html.append("<input type=\"hidden\" name=\"user_code\" value=\"")
            .append(htmlEscape(displayUserCode(normalized))).append("\">\n");
      } else if (usingAgentId) {
        // Audit B-P1b: preserve agent_id across the POST so transitionPendingAgent's agent_id
        // path resolves the same approval the GET rendered.
        html.append("<input type=\"hidden\" name=\"agent_id\" value=\"")
            .append(htmlEscape(agentId)).append("\">\n");
      }
      html.append("<input type=\"hidden\" name=\"csrf_token\" value=\"")
          .append(csrfToken).append("\">\n")
          .append("<fieldset>\n")
          .append("<legend>Your credentials</legend>\n")
          .append("<p>\n")
          .append("<label for=\"access_token\">Keycloak access token</label>\n")
          .append("<input type=\"password\" id=\"access_token\" name=\"access_token\"\n")
          .append("       autocomplete=\"off\" required\n")
          .append("       aria-describedby=\"access_token_hint\">\n")
          .append("<span id=\"access_token_hint\">Paste an access token for the user\n")
          .append("who should own this agent.</span>\n")
          .append("</p>\n")
          .append("</fieldset>\n")
          .append("<p>\n")
          .append("<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>\n")
          .append("<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\n")
          .append("</p>\n")
          .append("</form>\n");
    }
    html.append("</main>\n")
        .append("</body>\n")
        .append("</html>\n");
    return Response.ok(html.toString())
        .header("Set-Cookie",
            "agent_auth_csrf=" + csrfToken
                + "; Path=" + verifyCookiePath()
                + "; HttpOnly; SameSite=Strict"
                + (isSecureRequest() ? "; Secure" : ""))
        .build();
  }

  private static String generateCsrfToken() {
    byte[] bytes = new byte[16];
    USER_CODE_RNG.nextBytes(bytes);
    return java.util.HexFormat.of().formatHex(bytes);
  }

  private static boolean acceptsHtml(String acceptHeader) {
    return acceptHeader != null && acceptHeader.toLowerCase(Locale.ROOT).contains("text/html");
  }

  /**
   * Cheap presence check for the KC browser-session identity cookie. We don't validate freshness
   * here — that's the auth layer's job at POST time. We only need a boolean signal to decide
   * whether to bounce the browser through the login redirect on GET.
   */
  private boolean hasKeycloakIdentityCookie() {
    try {
      var cookies = session.getContext().getRequestHeaders().getCookies();
      return cookies != null
          && (cookies.containsKey("KEYCLOAK_IDENTITY")
              || cookies.containsKey("KEYCLOAK_IDENTITY_LEGACY"));
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  /**
   * Default OIDC client used for the browser login bounce. Operators can override by setting the
   * SPI config key {@code login-redirect-client-id} on the realm-resource provider; the test realm
   * ships with this client (public, directAccessGrants on, redirectUris="*") so the IT can exercise
   * the redirect direction end to end.
   */
  static final String LOGIN_REDIRECT_CLIENT_ID = "agent-auth-test-client";

  /**
   * Build the OIDC auth-endpoint URL the browser is redirected to when it hits {@code GET
   * /verify} unauthenticated. The {@code redirect_uri} comes back to {@code /verify}, preserving
   * any {@code user_code} query so the approval form renders correctly after login.
   */
  private URI buildLoginRedirectUri(String userCode, String agentId) {
    var verifyBuilder = session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
        .path("verify");
    if (userCode != null && !userCode.isBlank()) {
      verifyBuilder.queryParam("user_code", userCode);
    } else if (agentId != null && !agentId.isBlank()) {
      // Audit B-P1b: preserve agent_id across the login bounce so CIBA email deep links land
      // back on the right approval surface after the user re-authenticates.
      verifyBuilder.queryParam("agent_id", agentId);
    }
    String redirectUri = verifyBuilder.build().toString();
    byte[] stateBytes = new byte[16];
    USER_CODE_RNG.nextBytes(stateBytes);
    // Audit B-P1a / spec §8.11: pin max_age so the user is naturally re-authenticated when
    // landing on the approval page after the freshness window. OIDC core defines max_age as the
    // maximum elapsed seconds since the user's last active authentication; the IdP MUST prompt
    // for a fresh credential when the existing session is older. Matches the auth_time threshold
    // enforced in transitionPendingAgent so the GET-then-POST round trip stays consistent.
    return session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName())
        .path("protocol/openid-connect/auth")
        .queryParam("client_id", LOGIN_REDIRECT_CLIENT_ID)
        .queryParam("redirect_uri", redirectUri)
        .queryParam("response_type", "code")
        .queryParam("scope", "openid")
        .queryParam("max_age", Long.toString(approvalMaxAuthAgeSeconds()))
        .queryParam("state", java.util.HexFormat.of().formatHex(stateBytes))
        .build();
  }

  private String verifyCookiePath() {
    return session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
        .path("verify").build().getPath();
  }

  /**
   * Build the {@code .well-known/agent-configuration} discovery URL for the current realm. Used as
   * the {@code discovery="..."} parameter in the {@code WWW-Authenticate: AgentAuth} challenge per
   * spec §5.14, and emitted from the catalog and execute endpoints when authentication is missing
   * or insufficient.
   */
  private String agentConfigurationDiscoveryUrl() {
    return session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName())
        .path(".well-known/agent-configuration").build().toString();
  }

  private boolean isSecureRequest() {
    try {
      return "https".equalsIgnoreCase(
          session.getContext().getUri().getBaseUri().getScheme());
    } catch (Exception ignored) {
      return false;
    }
  }

  /**
   * Form-encoded companion to {@link #verifyApprove(Map) /verify/approve} and
   * {@link #verifyDeny(Map) /verify/deny}. Browser form submissions land here with
   * {@code user_code + decision + access_token} (or an {@code Authorization: Bearer} header).
   * Returns an HTML success/failure page rather than JSON.
   */
  @POST
  @Path("verify")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.TEXT_HTML)
  public Response verifyFormSubmit(
      @FormParam("user_code") String userCode,
      @FormParam("agent_id") String agentId,
      @FormParam("decision") String decision,
      @FormParam("access_token") String accessTokenFormField,
      @FormParam("csrf_token") String csrfFormToken,
      @HeaderParam("Authorization") String authHeader,
      @jakarta.ws.rs.CookieParam("agent_auth_csrf") String csrfCookieToken) {
    boolean haveUserCode = userCode != null && !userCode.isBlank();
    boolean haveAgentId = agentId != null && !agentId.isBlank();
    if ((!haveUserCode && !haveAgentId) || decision == null) {
      // Audit B-P1b: accept either user_code (device-auth path) or agent_id (CIBA email deep
      // link). Either is sufficient — both absent is still a 400.
      return htmlPage(400, "Missing user_code/agent_id or decision",
          "Please go back to the approval page and fill in the missing fields.");
    }
    if (!"approve".equals(decision) && !"deny".equals(decision)) {
      return htmlPage(400, "Invalid decision",
          "Decision must be <code>approve</code> or <code>deny</code>.");
    }
    String explicitToken = null;
    if ((authHeader == null || authHeader.isBlank())
        && accessTokenFormField != null && !accessTokenFormField.isBlank()) {
      explicitToken = accessTokenFormField;
    }
    // Double-submit CSRF guard: any browser-style submission (neither Bearer header nor
    // access_token form field) MUST carry a csrf_token that matches the cookie we planted on
    // the GET. Bearer-authenticated API callers already prove intent with the token itself, so
    // we only enforce CSRF on cookie-style flows. This matches the same-origin attack model of
    // OAuth browser flows and §8.11's "no session cookie alone" stance.
    boolean bearerAuth = (authHeader != null && !authHeader.isBlank()) || explicitToken != null;
    if (!bearerAuth && (csrfFormToken == null || csrfCookieToken == null
        || !csrfFormToken.equals(csrfCookieToken))) {
      return htmlPage(403, "CSRF check failed",
          "This request did not carry a matching CSRF token. Reload the approval page"
              + " and try again.");
    }
    Map<String, Object> body = new HashMap<>();
    if (haveUserCode) {
      body.put("user_code", userCode);
    } else {
      // Audit B-P1b: agent_id-only path. transitionPendingAgent's agent_id branch enforces
      // the host-owner check so a random user can't approve another user's pending agents.
      body.put("agent_id", agentId);
    }
    Response jsonResponse = transitionPendingAgent(body, "approve".equals(decision),
        explicitToken);
    int status = jsonResponse.getStatus();
    if (status == 200) {
      return htmlPage(200, "approve".equals(decision) ? "Approved" : "Denied",
          "approve".equals(decision)
              ? "Agent has been activated. You may close this window."
              : "Agent registration was denied. You may close this window.");
    }
    if (status == 401) {
      return htmlPage(401, "Authentication required",
          "The access token is missing, invalid, or expired. Please obtain a fresh token.");
    }
    if (status == 403) {
      // Audit B-P1a: distinguish fresh-auth-required (the most likely 403 here) from the other
      // 403s emitted by transitionPendingAgent, all of which boil down to "re-authenticate".
      return htmlPage(403, "Re-authentication required",
          "This approval requires a fresh login. Please return to the approval page; you will"
              + " be redirected through Keycloak to sign in again.");
    }
    if (status == 404) {
      return htmlPage(404, "Not found",
          "No pending approval matched that user_code.");
    }
    if (status == 410) {
      return htmlPage(410, "Approval closed",
          "This registration has already been denied. The client must retry with a new code.");
    }
    return htmlPage(status, "Approval failed", "Server returned status " + status + ".");
  }

  /**
   * AAP §7.1 device-authorization approval. The user whose registration is being approved
   * authenticates to Keycloak as a realm user and posts their {@code user_code} here. The endpoint
   * activates the agent and links the host to the approving user per §2.9.
   */
  @POST
  @Path("verify/approve")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response verifyApprove(Map<String, Object> requestBody) {
    return transitionPendingAgent(requestBody, /* approve= */ true, null);
  }

  /**
   * AAP §7.1 device-authorization denial. Per the spec: "User denial is terminal for that attempt.
   * The client MUST NOT automatically retry." The endpoint transitions the agent to
   * {@code rejected}; subsequent approve attempts return 410.
   */
  @POST
  @Path("verify/deny")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response verifyDeny(Map<String, Object> requestBody) {
    return transitionPendingAgent(requestBody, /* approve= */ false, null);
  }

  @SuppressWarnings("unchecked")
  private Response transitionPendingAgent(Map<String, Object> requestBody, boolean approve,
      String explicitToken) {
    org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator authenticator = new org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator(
        session);
    if (explicitToken != null && !explicitToken.isBlank()) {
      authenticator.setTokenString(explicitToken);
    }
    org.keycloak.services.managers.AuthenticationManager.AuthResult auth = authenticator
        .authenticate();
    if (auth == null) {
      return Response.status(401)
          .entity(Map.of("error", "authentication_required",
              "message", "Realm user access token required"))
          .build();
    }
    if (auth.user().getServiceAccountClientLink() != null) {
      return Response.status(403)
          .entity(Map.of("error", "user_required",
              "message", "Approval must come from a realm user, not a service account"))
          .build();
    }
    // Audit B-P1a / spec §8.11: completing approval or denial REQUIRES fresh user authentication.
    // A long-lived session token with a stale `auth_time` is insufficient — even if the bearer is
    // a real user, we don't know the human is currently at the keyboard. Reject early; the
    // browser flow naturally re-authenticates because verifyPage's login bounce sets max_age.
    //
    // Test-mode escape hatch: when `agent-auth.test-mode=true` is set on the JVM (only by the
    // testcontainers harness, see TestcontainersSupport), this freshness gate is skipped so the
    // integration suite can drive approvals with the long-lived bearer tokens our IT helpers mint
    // (which often have `auth_time` set by the password grant but may have aged across many
    // setup steps). The production path (no test-mode) keeps the new fresh-auth requirement.
    long maxAuthAgeSeconds = approvalMaxAuthAgeSeconds();
    boolean approvalTestMode = "true".equals(System.getProperty("agent-auth.test-mode"));
    if (!approvalTestMode && !isFreshAuth(auth, maxAuthAgeSeconds)) {
      return Response.status(403)
          .entity(Map.of("error", "fresh_authentication_required",
              "message", "Re-authenticate before approving or denying. Session auth_time is older"
                  + " than " + maxAuthAgeSeconds + "s."))
          .build();
    }

    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = null;
    if (requestBody != null) {
      Object rawCode = requestBody.get("user_code");
      Object rawAgentId = requestBody.get("agent_id");
      if (rawCode instanceof String uc && !uc.isBlank()) {
        agentData = storage.findAgentByUserCode(normalizeUserCode(uc));
      } else if (rawAgentId instanceof String aid && !aid.isBlank()) {
        // §7.2 CIBA path: the user found the pending approval through /inbox and submits the
        // agent_id directly rather than a user_code.
        agentData = storage.getAgent(aid);
        if (agentData != null && !isApprovingUserOwner(auth, agentData, storage)) {
          // An agent_id lookup bypasses user_code secrecy; enforce that the caller actually
          // owns the host the agent is registered under.
          return Response.status(403)
              .entity(Map.of("error", "not_approver",
                  "message", "Only the linked user may approve via agent_id"))
              .build();
        }
      } else {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request",
                "message", "Missing user_code or agent_id"))
            .build();
      }
    } else {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing user_code or agent_id"))
          .build();
    }
    if (agentData == null) {
      return Response.status(404)
          .entity(Map.of("error", "unknown_user_code",
              "message", "No pending approval for that identifier"))
          .build();
    }

    String status = (String) agentData.get("status");
    if ("rejected".equals(status) || "revoked".equals(status) || "claimed".equals(status)) {
      // §7.1: denial (and other terminal states) is terminal. Re-approval is not allowed.
      return Response.status(410)
          .entity(Map.of("error", "approval_terminal",
              "message", "Approval is no longer possible; agent is in a terminal state"))
          .build();
    }
    // §7.1 / §7.2 expiry: a stale approval (user_code or CIBA-emailed link) is no longer
    // redeemable. The mint time is stamped inside the approval blob in selectApprovalObject; if
    // it's older than userCodeExpirySeconds(), reject with 410. PendingAgentCleanup deletes
    // pending agents past 24h as a separate sweep, so an expired approval that hasn't been
    // cleaned yet still surfaces a clear error rather than silently succeeding hours later.
    Object approvalRaw = agentData.get("approval");
    if (approvalRaw instanceof Map<?, ?> approval) {
      Object issuedAtRaw = approval.get("issued_at_ms");
      if (issuedAtRaw instanceof Number issuedAt) {
        long ageMs = System.currentTimeMillis() - issuedAt.longValue();
        if (ageMs > userCodeExpirySeconds() * 1000L) {
          return Response.status(410)
              .entity(Map.of("error", "approval_expired",
                  "message", "Approval window has elapsed; client must re-register"))
              .build();
        }
      }
    }
    // Two approval contexts share this endpoint:
    // (a) §5.3 register / §5.6 reactivate — agent itself is `pending`.
    // (b) §5.4 capability-request — agent is `active`, and one or more grants are `pending`.
    boolean isCapabilityRequestApproval = "active".equals(status) && hasPendingGrants(agentData);
    if (!"pending".equals(status) && !isCapabilityRequestApproval) {
      return Response.status(409)
          .entity(Map.of("error", "invalid_state",
              "message", "Agent is not awaiting approval"))
          .build();
    }

    String userId = auth.user().getId();
    String agentId = (String) agentData.get("agent_id");
    String hostId = (String) agentData.get("host_id");
    String nowTs = nowTimestamp();
    // §3.1 TOFU collector — caps that flip pending → active here are the ones the linked user is
    // approving on this host for the first time. Names are appended to the host's
    // default_capabilities below so subsequent registrations auto-grant per §5.3
    // ("if the capabilities fall within its defaults, auto-approve").
    List<String> tofuAdds = new ArrayList<>();

    List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
        .get("agent_capability_grants");

    // §5.3 partial approval: if the request body carries a `capabilities` array, treat it as
    // the approved subset — pending grants not in the array are denied. When the array is
    // absent the user approved the whole pending set.
    Set<String> approvedSubset = null;
    if (approve && requestBody.get("capabilities") instanceof List<?> list) {
      approvedSubset = new LinkedHashSet<>();
      for (Object entry : list) {
        if (entry instanceof String s) {
          approvedSubset.add(s);
        }
      }
    }

    // §8.11: "Servers MUST require proof of physical presence (WebAuthn, hardware key) or use
    // an out-of-band approval channel (CIBA on a separate device) when approving capabilities
    // that can modify data or perform actions on behalf of the user." We enforce this on the
    // subset of pending grants that will actually flip to active.
    if (approve && grants != null) {
      boolean anyWriteCapable = false;
      for (Map<String, Object> grant : grants) {
        if (!"pending".equals(grant.get("status"))) {
          continue;
        }
        String capName = (String) grant.get("capability");
        if (approvedSubset != null && !approvedSubset.contains(capName)) {
          continue;
        }
        Map<String, Object> regCap = storage.getCapability(capName);
        if (regCap != null && Boolean.TRUE.equals(regCap.get("write_capable"))) {
          anyWriteCapable = true;
          break;
        }
      }
      if (anyWriteCapable && !hasProofOfPresence(auth)) {
        return Response.status(403)
            .entity(Map.of("error", "webauthn_required",
                "message",
                "§8.11: approval of write-capable grants requires proof of physical presence"
                    + " (WebAuthn or hardware key). Re-authenticate with a stronger factor"
                    + " and retry."))
            .build();
      }
    }

    if (approve) {
      if (!isCapabilityRequestApproval) {
        // Register/reactivate path: transition the agent itself. Per §5.3 the agent becomes
        // `active` even when every requested capability is denied — the status is driven by the
        // user's decision to engage, not by whether any grants came through.
        agentData.put("status", "active");
        agentData.put("activated_at", nowTs);
        agentData.put("user_id", userId);
      }
      // Phase 2 of the multi-tenant authz plan: snapshot the approver's KC entitlement once and
      // use it to gate each pending grant. Caps the approver can't grant under their current
      // org/role mapping flip to denied(reason=insufficient_authority) instead of active —
      // matches the existing partial-approval shape (user_denied), but distinguishes the cause
      // for audit/UI purposes.
      UserEntitlement approverEntitlement = loadUserEntitlement(userId);
      if (grants != null) {
        for (Map<String, Object> grant : grants) {
          if ("pending".equals(grant.get("status"))) {
            String capName = (String) grant.get("capability");
            boolean grantedThis = approvedSubset == null || approvedSubset.contains(capName);
            if (grantedThis) {
              Map<String, Object> registeredCap = storage.getCapability(capName);
              if (registeredCap == null
                  || !userEntitlementAllows(registeredCap, approverEntitlement)) {
                grant.put("status", "denied");
                grant.put("reason", "insufficient_authority");
                grant.remove("status_url");
                grant.remove("requested_constraints");
                continue;
              }
              grant.put("status", "active");
              grant.remove("status_url");
              grant.put("description", registeredCap.get("description"));
              if (registeredCap.containsKey("input")) {
                grant.put("input", registeredCap.get("input"));
              }
              if (registeredCap.containsKey("output")) {
                grant.put("output", registeredCap.get("output"));
              }
              grant.put("granted_by", userId);
              // §2.13: restore the agent's originally-requested constraint scope onto the
              // active grant. The pending grant stashed it under `requested_constraints` at
              // register/request-capability time so the user is approving the same scope the
              // agent declared. The approver doesn't redeclare scope at /verify/approve, so
              // dropping the stash here would widen the grant beyond what the agent asked for.
              Object stashed = grant.remove("requested_constraints");
              if (stashed instanceof Map<?, ?>) {
                grant.put("constraints", stashed);
              }
              tofuAdds.add(capName);
            } else {
              grant.put("status", "denied");
              grant.put("reason", "user_denied");
              grant.remove("status_url");
              grant.remove("requested_constraints");
            }
          }
        }
      }
      agentData.remove("user_code");
    } else {
      if (!isCapabilityRequestApproval) {
        agentData.put("status", "rejected");
        agentData.put("rejection_reason", "user_denied");
      }
      if (grants != null) {
        for (Map<String, Object> grant : grants) {
          if ("pending".equals(grant.get("status"))) {
            grant.put("status", "denied");
            grant.remove("status_url");
            // The user denied this grant — discard the requested scope so a denied entry
            // never carries leftover request metadata into storage or future responses.
            grant.remove("requested_constraints");
          }
        }
      }
      // Keep user_code so a subsequent approve attempt resolves the rejected agent and
      // returns 410 (§7.1: "client MUST NOT retry"), not 404. For capability-request denials
      // the user_code is cleared since the agent remains active and may receive fresh
      // approvals later.
      if (isCapabilityRequestApproval) {
        agentData.remove("user_code");
      }
    }
    agentData.put("updated_at", nowTs);
    agentData.remove("approval");
    storage.putAgent(agentId, agentData);

    if (approve) {
      // Three host-side updates can land here on approval, all keyed off the linked user:
      // §2.8 / §2.11 host activation — a pending host transitions to `active` once the user
      // approves an agent under it. Capability-request approvals run only on hosts that are
      // already active (the agent itself was active), so the flip is a no-op there.
      // §2.9 linking — the first delegated approval on an unlinked host binds the host to the
      // approving user. Capability-request approvals never re-link (host is already linked).
      // §3.1 TOFU defaults — every cap the user just approved on this host gets appended to
      // `default_capabilities` so future registrations auto-grant per §5.3.
      // All three flows write the host record once.
      Map<String, Object> hostData = storage.getHost(hostId);
      if (hostData != null) {
        boolean dirty = false;
        if ("pending".equals(hostData.get("status"))) {
          hostData.put("status", "active");
          hostData.put("activated_at", nowTs);
          dirty = true;
        }
        if (!isCapabilityRequestApproval && hostData.get("user_id") == null) {
          hostData.put("user_id", userId);
          dirty = true;
        }
        if (!tofuAdds.isEmpty()) {
          List<String> existing = hostDefaultCapabilities(hostData);
          for (String capName : tofuAdds) {
            if (!existing.contains(capName)) {
              existing.add(capName);
              dirty = true;
            }
          }
          hostData.put("default_capabilities", existing);
        }
        if (dirty) {
          hostData.put("updated_at", nowTs);
          storage.putHost(hostId, hostData);
        }
      }
    }

    return Response.ok(sanitizeAgentResponse(agentData)).build();
  }

  /**
   * Audit B-P1a / spec §8.11: returns {@code true} only when the access token's {@code auth_time}
   * claim (epoch seconds, derived from KC's IDToken) is within {@code maxAgeSeconds} of now. A
   * long-lived session whose {@code auth_time} predates the window is NOT fresh — the user must
   * re-authenticate before approve/deny is accepted. Defensive: a missing token, missing/zero
   * {@code auth_time}, or a future-dated stamp all return {@code false}.
   */
  private static boolean isFreshAuth(
      org.keycloak.services.managers.AuthenticationManager.AuthResult auth,
      long maxAgeSeconds) {
    if (auth == null || maxAgeSeconds <= 0L) {
      return false;
    }
    org.keycloak.representations.AccessToken token = auth.token();
    if (token == null) {
      return false;
    }
    // Keycloak's AccessToken extends IDToken; the OIDC auth_time claim (epoch seconds) is
    // surfaced via getAuth_time() returning Long. A null/zero claim means KC never stamped it
    // (e.g., service-account tokens) and is treated as not-fresh.
    Long authTime = token.getAuth_time();
    if (authTime == null || authTime <= 0L) {
      return false;
    }
    long nowSec = System.currentTimeMillis() / 1000L;
    long age = nowSec - authTime.longValue();
    if (age < 0L) {
      // Future-dated auth_time is treated as untrusted rather than always-fresh.
      return false;
    }
    return age <= maxAgeSeconds;
  }

  /**
   * Audit B-P1a: configured freshness window for completing approval/denial. Falls back to
   * {@link #DEFAULT_APPROVAL_MAX_AUTH_AGE_SECONDS} when the system property is unset, blank,
   * non-numeric, or non-positive.
   */
  private static long approvalMaxAuthAgeSeconds() {
    String raw = System.getProperty("agent-auth.approval.max-auth-age-seconds");
    if (raw != null && !raw.isBlank()) {
      try {
        long parsed = Long.parseLong(raw.trim());
        if (parsed > 0L) {
          return parsed;
        }
      } catch (NumberFormatException ignored) {
        // fall through to default
      }
    }
    return DEFAULT_APPROVAL_MAX_AUTH_AGE_SECONDS;
  }

  /**
   * §8.11 proof-of-presence check. Evaluates the access token's {@code amr} claim (RFC 8176) and
   * the session's authentication method reference note to determine whether the user proved
   * physical presence with a factor like WebAuthn, hardware key, or MFA. Returns {@code true} only
   * when the session is backed by an accepted factor.
   */
  private static boolean hasProofOfPresence(
      org.keycloak.services.managers.AuthenticationManager.AuthResult auth) {
    if (auth == null) {
      return false;
    }
    Set<String> accepted = Set.of(
        "hwk", "swk", "webauthn", "webauthn-passwordless", "mfa", "fpt", "otp");
    org.keycloak.representations.AccessToken token = auth.token();
    if (token != null) {
      Object amr = token.getOtherClaims().get("amr");
      if (amr instanceof List<?> list) {
        for (Object v : list) {
          if (v instanceof String s && accepted.contains(s)) {
            return true;
          }
        }
      }
    }
    // Fallback: inspect the session note that KC authenticators add during browser login.
    if (auth.session() != null) {
      String note = auth.session().getNote("AUTHENTICATION_METHOD_REFERENCE");
      if (note != null) {
        for (String part : note.split(",")) {
          if (accepted.contains(part.trim())) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * For the §7.2 CIBA / agent_id lookup path: confirm the authenticated caller owns the host that
   * the agent is registered under. Prevents a random realm user from approving another user's
   * pending agents by guessing agent_id.
   */
  private static boolean isApprovingUserOwner(
      org.keycloak.services.managers.AuthenticationManager.AuthResult auth,
      Map<String, Object> agentData, AgentAuthStorage storage) {
    if (auth == null || agentData == null) {
      return false;
    }
    String callerId = auth.user().getId();
    String hostId = (String) agentData.get("host_id");
    if (hostId == null) {
      return false;
    }
    Map<String, Object> hostData = storage.getHost(hostId);
    return hostData != null && callerId.equals(hostData.get("user_id"));
  }

  /**
   * AAP §7.2 in-Keycloak approval inbox. Authenticated realm users can list pending approvals for
   * any host linked to them (via {@code host.user_id}). Used as the stand-in for a real push
   * channel — users poll this endpoint to discover CIBA-routed approvals.
   */
  @GET
  @Path("inbox")
  @Produces(MediaType.APPLICATION_JSON)
  public Response inbox() {
    org.keycloak.services.managers.AuthenticationManager.AuthResult auth = new org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator(
        session)
        .authenticate();
    if (auth == null) {
      return Response.status(401)
          .entity(Map.of("error", "authentication_required",
              "message", "Realm user access token required"))
          .build();
    }
    // Audit B-P3a: align with transitionPendingAgent — service accounts must not browse the
    // approval inbox. The inbox is a user-facing surface; SA tokens belong to backend automation
    // and never carry an approving user identity.
    if (auth.user().getServiceAccountClientLink() != null) {
      return Response.status(403)
          .entity(Map.of("error", "user_required",
              "message", "Approval must come from a realm user, not a service account"))
          .build();
    }
    String userId = auth.user().getId();
    AgentAuthStorage storage = storage();
    List<Map<String, Object>> hosts = storage.findHostsByUser(userId);
    List<Map<String, Object>> pending = new ArrayList<>();
    for (Map<String, Object> host : hosts) {
      String hostId = (String) host.get("host_id");
      if (hostId == null) {
        continue;
      }
      for (Map<String, Object> agent : storage.findAgentsByHost(hostId)) {
        if ("pending".equals(agent.get("status")) || hasPendingGrants(agent)) {
          // Strip the internal `requested_constraints` stash; approvers see the same
          // compact pending-grant shape that the original register/request response carried.
          pending.add(sanitizeAgentResponse(agent));
        }
      }
    }
    return Response.ok(Map.of("pending_approvals", pending)).build();
  }

  private static Response htmlPage(int status, String heading, String body) {
    String html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Agent Auth</title>"
        + "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;"
        + "margin:2rem auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}</style></head>"
        + "<body><h1>" + htmlEscape(heading) + "</h1><p>" + body + "</p></body></html>";
    return Response.status(status).type(MediaType.TEXT_HTML).entity(html).build();
  }

  private static String htmlEscape(String raw) {
    if (raw == null) {
      return "";
    }
    return raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#x27;");
  }

  /**
   * Audit B-P2: shared display-sanitizer for attacker-controlled strings rendered into the approval
   * HTML (reason, host_name, binding_message, capability descriptions, constraint values). Strips
   * ASCII control characters (other than common whitespace), caps length, and HTML-escapes the
   * result. Returns an empty string for null/blank input. Maximum length is caller-controlled
   * because binding_message tolerates a longer cap (1000) than per-field details (200).
   */
  private static String sanitizeForDisplay(Object raw, int maxChars) {
    if (raw == null) {
      return "";
    }
    String s = raw.toString();
    if (s.isEmpty()) {
      return "";
    }
    StringBuilder cleaned = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\n' || c == '\r' || c == '\t') {
        cleaned.append(c);
        continue;
      }
      if (c < 0x20 || c == 0x7F) {
        // Drop ASCII control characters (NUL through unit-separator + DEL).
        continue;
      }
      if (c >= 0x80 && c <= 0x9F) {
        // Drop C1 control range (Unicode controls 0x80-0x9F).
        continue;
      }
      cleaned.append(c);
    }
    String trimmed = cleaned.toString();
    if (maxChars > 0 && trimmed.length() > maxChars) {
      trimmed = trimmed.substring(0, maxChars) + "…";
    }
    return htmlEscape(trimmed);
  }

  /**
   * Audit B-P2: render the request-level metadata an approver needs — the reason the agent supplied
   * (§5.3), the host's human-friendly name, and any CIBA binding_message — when those fields are
   * present. All values flow through {@link #sanitizeForDisplay} so attacker-supplied content can't
   * break out of the page.
   */
  @SuppressWarnings("unchecked")
  private void appendApprovalContext(StringBuilder html, Map<String, Object> pendingAgent,
      String hostId) {
    if (pendingAgent == null) {
      return;
    }
    String reason = sanitizeForDisplay(pendingAgent.get("reason"), 200);
    String hostName = null;
    if (hostId != null) {
      Map<String, Object> hostData = storage().getHost(hostId);
      if (hostData != null) {
        hostName = sanitizeForDisplay(hostData.get("name"), 200);
      }
    }
    String bindingMessage = null;
    Object approvalRaw = pendingAgent.get("approval");
    if (approvalRaw instanceof Map<?, ?> approval) {
      bindingMessage = sanitizeForDisplay(((Map<String, Object>) approval).get("binding_message"),
          1000);
    }
    boolean haveAny = !reason.isEmpty()
        || (hostName != null && !hostName.isEmpty())
        || (bindingMessage != null && !bindingMessage.isEmpty());
    if (!haveAny) {
      return;
    }
    html.append("<dl>\n");
    if (hostName != null && !hostName.isEmpty()) {
      html.append("<dt>Host</dt><dd>").append(hostName).append("</dd>\n");
    }
    if (!reason.isEmpty()) {
      html.append("<dt>Reason</dt><dd>").append(reason).append("</dd>\n");
    }
    if (bindingMessage != null && !bindingMessage.isEmpty()) {
      html.append("<dt>Binding message</dt><dd>").append(bindingMessage).append("</dd>\n");
    }
    html.append("</dl>\n");
  }

  /**
   * Audit B-P2: enumerate the pending grants on this approval with their registry-supplied
   * descriptions and the agent's requested constraint scope. Approvers can't make a meaningful
   * decision without seeing what each capability does. Constraints come from the internal
   * `requested_constraints` stash that {@link #transitionPendingAgent} promotes to `constraints` on
   * approval. All values run through {@link #sanitizeForDisplay} before reaching the page.
   */
  @SuppressWarnings("unchecked")
  private void appendPendingGrants(StringBuilder html, Map<String, Object> pendingAgent) {
    if (pendingAgent == null) {
      return;
    }
    Object rawGrants = pendingAgent.get("agent_capability_grants");
    if (!(rawGrants instanceof List<?>)) {
      return;
    }
    List<Map<String, Object>> pending = new ArrayList<>();
    for (Object entry : (List<?>) rawGrants) {
      if (entry instanceof Map<?, ?> g
          && "pending".equals(((Map<String, Object>) g).get("status"))) {
        pending.add((Map<String, Object>) g);
      }
    }
    if (pending.isEmpty()) {
      return;
    }
    html.append("<h3>Requested capabilities</h3>\n").append("<ul>\n");
    for (Map<String, Object> grant : pending) {
      String capName = sanitizeForDisplay(grant.get("capability"), 200);
      Map<String, Object> registered = null;
      Object capRaw = grant.get("capability");
      if (capRaw instanceof String capStr && !capStr.isBlank()) {
        registered = storage().getCapability(capStr);
      }
      String description = registered == null
          ? ""
          : sanitizeForDisplay(registered.get("description"), 200);
      html.append("<li><strong>").append(capName).append("</strong>");
      if (!description.isEmpty()) {
        html.append(" — ").append(description);
      }
      Object constraintsRaw = grant.get("requested_constraints");
      if (constraintsRaw instanceof Map<?, ?> constraints && !constraints.isEmpty()) {
        html.append("<br><small>Requested constraints: ")
            .append(sanitizeForDisplay(constraints.toString(), 200))
            .append("</small>");
      }
      html.append("</li>\n");
    }
    html.append("</ul>\n");
  }

  @SuppressWarnings("unchecked")
  private static boolean hasPendingGrants(Map<String, Object> agentData) {
    Object raw = agentData.get("agent_capability_grants");
    if (!(raw instanceof List<?>)) {
      return false;
    }
    for (Object entry : (List<?>) raw) {
      if (entry instanceof Map<?, ?> g
          && "pending".equals(((Map<String, Object>) g).get("status"))) {
        return true;
      }
    }
    return false;
  }

  /**
   * §5.3 / §5.4: pending registrations and capability requests return a compact grant shape
   * ({@code capability}, {@code status}, optional {@code status_url}) without echoing the
   * agent-requested constraint scope. Internally we stash the requested scope under
   * {@code requested_constraints} on each pending grant so {@link #transitionPendingAgent} can
   * promote it to {@code constraints} on approval (§2.13: server MUST NOT widen scope beyond what
   * was requested without new approval). This helper returns a shallow agent-data copy whose grants
   * list strips the internal {@code requested_constraints} key so the wire shape stays compact
   * while storage retains the full scope.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> sanitizeAgentResponse(Map<String, Object> agentData) {
    if (agentData == null) {
      return null;
    }
    Object rawGrants = agentData.get("agent_capability_grants");
    if (!(rawGrants instanceof List<?>)) {
      return agentData;
    }
    Map<String, Object> copy = new HashMap<>(agentData);
    copy.put("agent_capability_grants",
        sanitizeGrantsForResponse((List<Map<String, Object>>) rawGrants));
    return copy;
  }

  /**
   * Builds a wire-shape copy of a grants list, stripping internal-only keys that must not appear in
   * §5.3 / §5.4 / §5.7 grant objects. Currently strips:
   * <ul>
   * <li>{@code requested_constraints} — internal stash for §2.13 scope preservation across the
   * pending → active transition.</li>
   * <li>{@code status_url} — the per-grant status polling URL. Catalog/registration responses MUST
   * NOT include it on the grant object (§5.3/§5.4: pending grants are {@code {capability,
   * status}}). The status URL is exposed as a documented extension via {@code GET
   * /agent/{agentId}/capabilities/{capabilityName}/status}; the helper is retained only as a
   * defense-in-depth strip in case a future code path stamps it on a grant.</li>
   * </ul>
   */
  private static List<Map<String, Object>> sanitizeGrantsForResponse(
      List<Map<String, Object>> grants) {
    List<Map<String, Object>> out = new ArrayList<>(grants.size());
    for (Map<String, Object> grant : grants) {
      if (grant.containsKey("requested_constraints") || grant.containsKey("status_url")) {
        Map<String, Object> grantCopy = new HashMap<>(grant);
        grantCopy.remove("requested_constraints");
        grantCopy.remove("status_url");
        out.add(grantCopy);
      } else {
        out.add(grant);
      }
    }
    return out;
  }

  private static boolean isEd25519Jwk(Map<String, Object> jwk) {
    try {
      return jwk != null && com.nimbusds.jose.jwk.Curve.Ed25519
          .equals(OctetKeyPair.parse(jwk).getCurve());
    } catch (Exception e) {
      return false;
    }
  }

  private static String nowTimestamp() {
    return Instant.now().toString();
  }

  private static String futureTimestamp(long seconds) {
    return Instant.now().plusSeconds(seconds).toString();
  }

  /**
   * Audit E-F4: Parse a grant's {@code expires_at} field (stored as ISO-8601 per the codebase
   * convention used by {@link #futureTimestamp}/{@link #nowTimestamp}). Returns {@code null} when
   * the value is absent, blank, or unparseable — callers treat null as "no expiry".
   */
  private static Instant parseGrantExpiresAt(Object raw) {
    if (raw == null) {
      return null;
    }
    if (raw instanceof Instant i) {
      return i;
    }
    if (raw instanceof String s) {
      String trimmed = s.trim();
      if (trimmed.isEmpty()) {
        return null;
      }
      try {
        return Instant.parse(trimmed);
      } catch (RuntimeException ignored) {
        return null;
      }
    }
    return null;
  }

  /**
   * Audit E-F3 / §§2.11, 4.5: terminal hosts (revoked / rejected / expired / claimed / any non-
   * active state) must not authorize execute. Returns null when the host is active, or the
   * appropriate 403 Response otherwise. Caller threads {@code hostData} from storage.
   */
  private static Response hostMustBeActive(Map<String, Object> hostData) {
    if (hostData == null) {
      return Response.status(403)
          .entity(Map.of("error", "unauthorized", "message", "Host not found"))
          .build();
    }
    Object statusObj = hostData.get("status");
    if ("active".equals(statusObj)) {
      return null;
    }
    if ("revoked".equals(statusObj)) {
      return Response.status(403)
          .entity(Map.of("error", "host_revoked", "message", "Host is revoked"))
          .build();
    }
    if ("pending".equals(statusObj)) {
      return Response.status(403)
          .entity(Map.of("error", "host_pending", "message", "Host is pending"))
          .build();
    }
    if ("rejected".equals(statusObj)) {
      return Response.status(403)
          .entity(Map.of("error", "host_rejected", "message", "Host is rejected"))
          .build();
    }
    String status = statusObj instanceof String s ? s : "unknown";
    return Response.status(403)
        .entity(Map.of("error", "unauthorized",
            "message", "Host is not active (status=" + status + ")"))
        .build();
  }

  /**
   * Audit E-F4 / spec §3.3: a grant is effective only when {@code status == "active"} AND its
   * {@code expires_at} is absent/null/blank OR strictly in the future relative to {@code now}.
   * Centralised so execute, introspect, and the constraint-check / capabilities-claim filters
   * cannot drift apart.
   */
  private static boolean isEffectiveActiveGrant(Map<String, Object> grant, Instant now) {
    if (grant == null || !"active".equals(grant.get("status"))) {
      return false;
    }
    Instant expiresAt = parseGrantExpiresAt(grant.get("expires_at"));
    if (expiresAt == null) {
      return true;
    }
    return expiresAt.isAfter(now);
  }

  private boolean isJtiReplay(SignedJWT jwt, String jti) {
    long ttlSeconds = 60;
    try {
      if (jwt.getJWTClaimsSet().getExpirationTime() != null) {
        long ttlMillis = jwt.getJWTClaimsSet().getExpirationTime().getTime()
            - System.currentTimeMillis();
        ttlSeconds = Math.max(60, (ttlMillis + 999) / 1000);
      }
    } catch (Exception ignored) {
      // Malformed JWTs fail elsewhere; keep a short single-use TTL for this defensive path.
    }
    return !session.singleUseObjects().putIfAbsent("agentauth:jti:" + jti, ttlSeconds);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> resolveAgentPublicKeyMap(Map<String, Object> agentData,
      SignedJWT jwt) {
    String agentJwksUrl = (String) agentData.get("agent_jwks_url");
    if (agentJwksUrl != null && !agentJwksUrl.isBlank()) {
      String kid = jwt.getHeader().getKeyID();
      if (kid == null || kid.isBlank()) {
        kid = (String) agentData.get("agent_kid");
      }
      if (kid == null || kid.isBlank()) {
        throw new IllegalArgumentException("Missing kid for agent_jwks_url");
      }
      return JWKS_CACHE.resolve(agentJwksUrl, kid);
    }
    return (Map<String, Object>) agentData.get("agent_public_key");
  }

  private String issuerUrl() {
    return session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).build().toString()
        + "/agent-auth";
  }

  private Map<String, Object> buildApprovalObject(String agentId) {
    Map<String, Object> approval = new HashMap<>();
    approval.put("method", "admin");
    approval.put("expires_in", userCodeExpirySeconds());
    approval.put("interval", DEFAULT_APPROVAL_INTERVAL);
    approval.put("status_url",
        session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
            .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
            .path("agent").path("status").queryParam("agent_id", agentId).build().toString());
    return approval;
  }

  /**
   * §7 approval-method selection shared by the register, capability-request, and reactivate
   * handlers so the three paths emit a consistent shape:
   *
   * <ul>
   * <li>Delegated + linked host → CIBA (§7.3 "prefer CIBA when a browser-controlling agent may be
   * present"; once the host is linked the user is known and the inbox delivers the prompt).</li>
   * <li>Delegated + unlinked host → device_authorization.</li>
   * <li>Autonomous or admin-mediated paths → legacy "admin" extension object.</li>
   * </ul>
   *
   * Side effect: writes a {@code user_code} into {@code agentData} when emitting device_auth.
   */
  private Map<String, Object> selectApprovalObject(String agentId,
      Map<String, Object> agentData, Map<String, Object> hostData, String mode,
      String bindingMessage) {
    boolean hostLinked = hostData != null && hostData.get("user_id") != null;
    if ("delegated".equals(mode) && hostLinked) {
      Map<String, Object> approval = buildCibaApprovalObject(agentId, bindingMessage);
      // §7.2 expiry: same stamp as the device-auth path — verifyApprove enforces the window for
      // both flows by reading approval.issued_at_ms.
      approval.put("issued_at_ms", System.currentTimeMillis());
      // §7.2 push delivery: best-effort email to the linked user. Failure is logged and
      // swallowed by the notifier so the approval response itself never breaks on SMTP issues
      // — the inbox endpoint remains the always-on fallback.
      new com.github.chh.keycloak.agentauth.notify.CibaEmailNotifier(session)
          .notifyApproval(agentId, agentData, hostData, bindingMessage);
      return approval;
    }
    if ("delegated".equals(mode)) {
      String userCode = generateUserCode();
      agentData.put("user_code", userCode);
      // §7.1 expiry: stamp the mint time inside the device-auth approval object so verifyApprove
      // can reject stale codes. The stamp lives in `approval.issued_at_ms` because (a) the approval
      // blob is the JSON-serialized portion that survives JpaStorage round-trip — top-level
      // unknown keys are dropped by the typed-column schema, and (b) it groups the timestamp with
      // the approval it belongs to. Capability-request and reactivate flows mint a fresh approval
      // (and a fresh stamp) each time, so the field always tracks the latest pending approval.
      Map<String, Object> approval = buildDeviceAuthApprovalObject(agentId, userCode);
      approval.put("issued_at_ms", System.currentTimeMillis());
      return approval;
    }
    return buildApprovalObject(agentId);
  }

  /**
   * §7.1 user_code expiry threshold (seconds). Operator-configurable per-realm via the {@code
   * agent_auth_approval_expires_in_seconds} attribute; falls back to
   * {@link #DEFAULT_APPROVAL_EXPIRES_IN}. Used both in {@code expires_in} responses (so what we
   * advertise matches what we enforce) and in the verifyApprove staleness check.
   */
  private long userCodeExpirySeconds() {
    RealmModel realm = session.getContext().getRealm();
    if (realm != null) {
      String raw = realm.getAttribute("agent_auth_approval_expires_in_seconds");
      if (raw != null && !raw.isBlank()) {
        try {
          long parsed = Long.parseLong(raw.trim());
          if (parsed > 0) {
            return parsed;
          }
        } catch (NumberFormatException ignored) {
          // fall through to default
        }
      }
    }
    return DEFAULT_APPROVAL_EXPIRES_IN;
  }

  /**
   * §7.2 CIBA approval object. No {@code user_code}/{@code verification_uri} — the agent polls
   * {@code /agent/status} and the linked user discovers the pending approval via the in-Keycloak
   * inbox ({@code GET /agent-auth/inbox}). {@code binding_message} is optional and echoed back if
   * the register request supplied one.
   */
  private Map<String, Object> buildCibaApprovalObject(String agentId, String bindingMessage) {
    String statusUrl = session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
        .path("agent").path("status").queryParam("agent_id", agentId).build().toString();
    Map<String, Object> approval = new HashMap<>();
    approval.put("method", "ciba");
    approval.put("expires_in", userCodeExpirySeconds());
    approval.put("interval", DEFAULT_APPROVAL_INTERVAL);
    // Audit B-P3b: spec §7.5 / §10.10 keep `status_url` out of the core approval object. Move it
    // under a namespaced extensions map (matches the README's documented "extensions" pattern)
    // so existing clients in this repo can still reach the polling URL while a strict reader
    // sees a spec-clean approval shape.
    approval.put("extensions", Map.of("status_url", statusUrl));
    if (bindingMessage != null && !bindingMessage.isBlank()) {
      approval.put("binding_message", bindingMessage);
    }
    return approval;
  }

  private Map<String, Object> buildDeviceAuthApprovalObject(String agentId, String userCodeRaw) {
    String display = displayUserCode(userCodeRaw);
    String verifyBase = issuerUrl() + "/verify";
    String statusUrl = session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
        .path("agent").path("status").queryParam("agent_id", agentId).build().toString();
    Map<String, Object> approval = new HashMap<>();
    approval.put("method", "device_authorization");
    approval.put("expires_in", userCodeExpirySeconds());
    approval.put("interval", DEFAULT_APPROVAL_INTERVAL);
    approval.put("user_code", display);
    approval.put("verification_uri", verifyBase);
    approval.put("verification_uri_complete", verifyBase + "?user_code=" + display);
    // Audit B-P3b: see CIBA path above — `status_url` belongs under the extensions namespace.
    approval.put("extensions", Map.of("status_url", statusUrl));
    return approval;
  }

  private static final java.security.SecureRandom USER_CODE_RNG = new java.security.SecureRandom();
  private static final int USER_CODE_LENGTH = 8;

  private static String generateUserCode() {
    char[] chars = new char[USER_CODE_LENGTH];
    for (int i = 0; i < USER_CODE_LENGTH; i++) {
      chars[i] = (char) ('A' + USER_CODE_RNG.nextInt(26));
    }
    return new String(chars);
  }

  private static String displayUserCode(String raw) {
    return raw.substring(0, 4) + "-" + raw.substring(4);
  }

  private static String normalizeUserCode(String userCode) {
    if (userCode == null) {
      return null;
    }
    return userCode.replace("-", "").toUpperCase(Locale.ROOT);
  }

  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  private List<URI> upstreamCandidateUris(URI uri) {
    String host = uri.getHost();
    if (!"127.0.0.1".equals(host) && !"localhost".equals(host)) {
      return List.of(uri);
    }

    List<String> hosts = List.of(
        "host.testcontainers.internal",
        "host.docker.internal",
        "172.17.0.1");
    List<URI> candidates = new ArrayList<>();
    for (String targetHost : hosts) {
      candidates.add(URI.create(uri.getScheme() + "://" + targetHost + ":" + uri.getPort()
          + uri.getRawPath()
          + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery())));
    }
    return candidates;
  }

  private String computeGrantStatus(String agentId, String capabilityName) {
    Map<String, Object> agentData = storage().getAgent(agentId);
    if (agentData == null) {
      return "not_granted";
    }
    // §2.12 grant_status semantics: a grant only counts as "granted" when the agent itself is
    // active AND the agent's owning host is active. Pre-2026-04 the catalog endpoints would emit
    // grant_status=granted even if the agent had been revoked/expired or if the host was pending,
    // because computeGrantStatus only inspected the per-grant status row. Surface that state by
    // demoting to "not_granted" when the principal cannot exercise the grant anyway.
    if (!"active".equals(agentData.get("status"))) {
      return "not_granted";
    }
    String hostId = (String) agentData.get("host_id");
    if (hostId == null || hostId.isBlank()) {
      return "not_granted";
    }
    Map<String, Object> hostData = storage().getHost(hostId);
    if (hostData == null || !"active".equals(hostData.get("status"))) {
      return "not_granted";
    }
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
        .get("agent_capability_grants");
    if (grants == null) {
      return "not_granted";
    }
    for (Map<String, Object> grant : grants) {
      if (capabilityName.equals(grant.get("capability")) && "active".equals(grant.get("status"))) {
        return "granted";
      }
    }
    return "not_granted";
  }

  /**
   * §3.1 host.default_capabilities accessor. Returns a mutable snapshot list of cap names (always
   * non-null; empty when the host has no defaults yet or {@code hostData} is null).
   */
  @SuppressWarnings("unchecked")
  private static List<String> hostDefaultCapabilities(Map<String, Object> hostData) {
    if (hostData == null) {
      return new ArrayList<>();
    }
    Object raw = hostData.get("default_capabilities");
    if (!(raw instanceof List<?>)) {
      return new ArrayList<>();
    }
    List<String> out = new ArrayList<>();
    for (Object item : (List<?>) raw) {
      if (item instanceof String s && !s.isBlank()) {
        out.add(s);
      }
    }
    return out;
  }

  private static List<Map<String, Object>> copyGrantDefaults(List<Map<String, Object>> grants) {
    List<Map<String, Object>> defaults = new ArrayList<>();
    for (Map<String, Object> grant : grants) {
      if ("denied".equals(grant.get("status"))) {
        continue;
      }
      defaults.add(new HashMap<>(grant));
    }
    return defaults;
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> buildReactivationGrants(Map<String, Object> hostData) {
    Object rawDefaults = hostData.getOrDefault("default_capability_grants", List.of());
    if (!(rawDefaults instanceof List<?>)) {
      return List.of();
    }
    List<String> hostDefaults = hostDefaultCapabilities(hostData);

    List<Map<String, Object>> grants = new ArrayList<>();
    for (Object rawDefault : (List<?>) rawDefaults) {
      if (!(rawDefault instanceof Map<?, ?>)) {
        continue;
      }

      Map<String, Object> defaultGrant = (Map<String, Object>) rawDefault;
      String capName = (String) defaultGrant.get("capability");
      if (capName == null) {
        continue;
      }

      Map<String, Object> registeredCap = storage().getCapability(capName);
      if (registeredCap == null) {
        continue;
      }

      // §5.6: "Determine the host's current default capabilities and grant them to the agent,
      // following the same auto-approval logic as registration." Apply the same TOFU rule as
      // registerAgent: cap auto-grants if !requires_approval OR it's in the host's
      // default_capabilities (the per-host TOFU set populated by prior approvals).
      boolean inHostDefaults = hostDefaults.contains(capName);
      boolean needsApproval = Boolean.TRUE.equals(registeredCap.get("requires_approval"))
          && !inHostDefaults;
      Map<String, Object> grant = new HashMap<>();
      grant.put("capability", capName);
      if (needsApproval) {
        grant.put("status", "pending");
        // §5.4: pending grants on the wire are compact {capability, status}. Per-grant status URL
        // is exposed only as a documented extension endpoint, not on the grant object.
      } else {
        grant.put("status", "active");
        grant.put("description", registeredCap.get("description"));
        if (registeredCap.containsKey("input")) {
          grant.put("input", registeredCap.get("input"));
        }
        if (registeredCap.containsKey("output")) {
          grant.put("output", registeredCap.get("output"));
        }
        grant.put("granted_by", hostData.get("host_id"));
        if (defaultGrant.containsKey("constraints")) {
          grant.put("constraints", defaultGrant.get("constraints"));
        }
      }
      grants.add(grant);
    }
    return grants;
  }

  private static List<String> unknownConstraintOperators(Map<String, Object> constraints) {
    if (constraints == null) {
      return List.of();
    }
    Set<String> unknown = new LinkedHashSet<>();
    for (Object constraintValue : constraints.values()) {
      if (constraintValue instanceof Map<?, ?> opMap) {
        for (Object key : opMap.keySet()) {
          if (!(key instanceof String) || !SUPPORTED_CONSTRAINT_OPERATORS.contains(key)) {
            unknown.add(String.valueOf(key));
          }
        }
      }
    }
    return new ArrayList<>(unknown);
  }

  private static Response unknownConstraintOperatorResponse(List<String> unknownOperators) {
    String firstOperator = unknownOperators.isEmpty() ? "" : unknownOperators.get(0);
    return Response.status(400)
        .entity(Map.of("error", "unknown_constraint_operator", "message",
            "Unknown constraint operator: " + firstOperator, "unknown_operators",
            unknownOperators))
        .build();
  }

  private static Response enforceRateLimit(String key, int limit, long windowMs) {
    long now = System.currentTimeMillis();
    Map<String, Object> bucket = RATE_LIMITS.computeIfAbsent(key, ignored -> {
      Map<String, Object> created = new HashMap<>();
      created.put("window_start", now);
      created.put("count", 0);
      return created;
    });

    synchronized (bucket) {
      long windowStart = ((Number) bucket.get("window_start")).longValue();
      int count = ((Number) bucket.get("count")).intValue();
      if (now - windowStart >= windowMs) {
        windowStart = now;
        count = 0;
      }
      count++;
      bucket.put("window_start", windowStart);
      bucket.put("count", count);
      if (count > limit) {
        long retryAfterSeconds = Math.max(1L, (windowMs - (now - windowStart) + 999L) / 1000L);
        return Response.status(429)
            .header("Retry-After", String.valueOf(retryAfterSeconds))
            .entity(Map.of("error", "rate_limited", "message", "Too many requests"))
            .build();
      }
    }
    return null;
  }

  /**
   * Phase 1 of the multi-tenant authz plan: resolve the caller's owning KC user from whichever
   * principal type was verified. Agent's user_id is set during register (delegated) or claim
   * (autonomous); host's user_id is set when an admin or approval flow links the host. Returns null
   * when the principal isn't yet linked to a KC user.
   */
  private static String resolveEffectiveUserId(Map<String, Object> agentData,
      Map<String, Object> hostData) {
    if (agentData != null) {
      Object uid = agentData.get("user_id");
      if (uid instanceof String uidStr && !uidStr.isBlank()) {
        return uidStr;
      }
    }
    if (hostData != null) {
      Object uid = hostData.get("user_id");
      if (uid instanceof String uidStr && !uidStr.isBlank()) {
        return uidStr;
      }
    }
    return null;
  }

  /**
   * Snapshot of the KC user's realm-roles and organization memberships used by the Phase 1
   * user-entitlement gate on {@code /capability/list} and {@code /capability/describe}.
   *
   * <p>
   * Package-private (was private) so {@link AgentAuthAdminResourceProvider#approveCapability} can
   * reuse the same gate at admin-approval time (AAP-ADMIN-002).
   */
  record UserEntitlement(Set<String> orgs, Set<String> roles) {
  }

  /**
   * Loads the entitlement snapshot for the given user_id. Returns null when the id is null or the
   * user no longer exists; callers treat null as "no orgs, no roles" — which makes any cap with an
   * org_id or required_role gate invisible to the caller. If KC Organizations isn't enabled on this
   * realm, the org set is empty (org-scoped caps become effectively invisible — operators that mint
   * org-scoped caps without enabling the feature are misconfigured).
   *
   * <p>
   * Instance wrapper kept for existing callers; the static
   * {@link #loadUserEntitlement(KeycloakSession, String)} does the real work and is what
   * {@link AgentAuthAdminResourceProvider} reuses (AAP-ADMIN-002).
   */
  private UserEntitlement loadUserEntitlement(String userId) {
    return loadUserEntitlement(session, userId);
  }

  /**
   * Static form of {@link #loadUserEntitlement(String)}; package-private so the admin provider can
   * gate admin-mediated grant approvals through the same entitlement snapshot.
   */
  static UserEntitlement loadUserEntitlement(KeycloakSession session, String userId) {
    if (userId == null || userId.isBlank()) {
      return null;
    }
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      return null;
    }
    UserModel user = session.users().getUserById(realm, userId);
    if (user == null) {
      return null;
    }
    Set<String> roles = new HashSet<>();
    user.getRealmRoleMappingsStream().map(RoleModel::getName).forEach(roles::add);
    Set<String> orgs = new HashSet<>();
    if (realm.isOrganizationsEnabled()) {
      // Defense-in-depth: realm.isOrganizationsEnabled() short-circuits the common feature-off
      // case, but a deployment could in theory have the realm flag on while the server-level
      // feature flag is off, in which case session.getProvider may return null OR throw. Treat
      // any failure as "user has no orgs", which makes org-gated caps invisible (fail-safe).
      try {
        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
        if (orgProvider != null) {
          orgProvider.getByMember(user).map(org -> org.getId()).forEach(orgs::add);
        }
      } catch (RuntimeException ignored) {
        // NOPMD: provider unavailable; orgs stays empty.
      }
    }
    return new UserEntitlement(orgs, roles);
  }

  /**
   * Phase 1 user-entitlement gate. Returns true iff the cap is grantable to the entitlement:
   * {@code (cap.organization_id IS NULL OR org_id ∈ entitlement.orgs)} AND
   * {@code (cap.required_role IS NULL OR required_role ∈ entitlement.roles)}. A null entitlement
   * (user not linked or not found) only passes caps with both gates unset.
   *
   * <p>
   * Package-private (was private) so the admin provider can mirror the user-approval gate at
   * admin-approval time (AAP-ADMIN-002).
   */
  static boolean userEntitlementAllows(Map<String, Object> cap,
      UserEntitlement entitlement) {
    Object rawOrgId = cap.get("organization_id");
    if (rawOrgId instanceof String orgId && !orgId.isBlank()
        && (entitlement == null || !entitlement.orgs().contains(orgId))) {
      return false;
    }
    Object rawRequiredRole = cap.get("required_role");
    if (rawRequiredRole instanceof String role && !role.isBlank()
        && (entitlement == null || !entitlement.roles().contains(role))) {
      return false;
    }
    return true;
  }

  @Override
  public void close() {
    // no-op: nothing to release
  }
}
