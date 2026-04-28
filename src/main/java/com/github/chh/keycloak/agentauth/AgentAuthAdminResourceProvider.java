package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class AgentAuthAdminResourceProvider implements AdminRealmResourceProvider {

  private static final Pattern CAPABILITY_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_]+");
  private KeycloakSession session;
  private AdminPermissionEvaluator auth;
  private AdminEventBuilder adminEvent;

  public AgentAuthAdminResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  private AgentAuthStorage storage() {
    return session.getProvider(AgentAuthStorage.class);
  }

  @Override
  public Object getResource(KeycloakSession session, RealmModel realm,
      AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
    this.session = session;
    this.auth = auth;
    this.adminEvent = adminEvent;
    return this;
  }

  @POST
  @Path("capabilities")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response registerCapability(Map<String, Object> requestBody) {
    requireManageRealm();
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    String name = (String) requestBody.get("name");

    if (name == null || name.isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing name"))
          .build();
    }

    if (!CAPABILITY_NAME_PATTERN.matcher(name).matches()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "Capability name must match [a-zA-Z0-9_]+"))
          .build();
    }

    String visibility = (String) requestBody.getOrDefault("visibility", "authenticated");
    if (!"authenticated".equals(visibility) && !"public".equals(visibility)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Invalid visibility")).build();
    }

    // AAP-ADMIN-005: realm-scoped capability writes MUST NOT carry an `organization_id` body
    // field. Org-scoped writes belong on /organizations/{orgId}/capabilities, where the path
    // determines the tenant. Without this rejection a caller could mint a cap that shows up
    // in another org's listings (validateGateFields only checks shape, not whether the body
    // is permitted on this endpoint).
    if (requestBody.containsKey("organization_id")) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message",
              "organization_id is not accepted on realm-scoped capability endpoints; use"
                  + " /organizations/{orgId}/capabilities for org-scoped writes"))
          .build();
    }

    Response capabilityFieldValidation = validateCapabilityFields(requestBody);
    if (capabilityFieldValidation != null) {
      return capabilityFieldValidation;
    }

    Response gateValidation = validateGateFields(requestBody);
    if (gateValidation != null) {
      return gateValidation;
    }

    if (storage().putCapabilityIfAbsent(name, requestBody) != null) {
      return Response.status(409)
          .entity(Map.of("error", "capability_exists", "message", "Capability already exists"))
          .build();
    }

    emitAdminEvent("agent-auth/capability/" + name, OperationType.CREATE, requestBody);
    return Response.status(201).entity(requestBody).build();
  }

  @PUT
  @Path("capabilities/{name}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response updateCapability(@PathParam("name") String name,
      Map<String, Object> requestBody) {
    requireManageRealm();
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    AgentAuthStorage storage = storage();
    Map<String, Object> existingCapability = storage.getCapability(name);
    if (existingCapability == null) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }

    // AAP-ADMIN-005: realm-scoped updates MUST NOT carry an `organization_id` body field. See
    // registerCapability for full rationale; org-scoped writes belong on the path-derived
    // /organizations/{orgId}/capabilities endpoint.
    if (requestBody.containsKey("organization_id")) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message",
              "organization_id is not accepted on realm-scoped capability endpoints; use"
                  + " /organizations/{orgId}/capabilities for org-scoped writes"))
          .build();
    }

    Response capabilityFieldValidation = validateCapabilityFields(requestBody);
    if (capabilityFieldValidation != null) {
      return capabilityFieldValidation;
    }

    Response gateValidation = validateGateFields(requestBody);
    if (gateValidation != null) {
      return gateValidation;
    }

    Map<String, Object> updatedCapability = new HashMap<>(requestBody);
    updatedCapability.put("name", name);
    storage.putCapability(name, updatedCapability);

    emitAdminEvent("agent-auth/capability/" + name, OperationType.UPDATE, updatedCapability);
    return Response.ok(updatedCapability).build();
  }

  @DELETE
  @Path("capabilities/{name}")
  public Response deleteCapability(@PathParam("name") String name) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    Map<String, Object> removedCapability = storage.getCapability(name);
    if (removedCapability == null) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }
    storage.removeCapability(name);

    emitAdminEvent("agent-auth/capability/" + name, OperationType.DELETE, removedCapability);
    return Response.noContent().build();
  }

  @POST
  @Path("agents/{id}/expire")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response expireAgent(@PathParam("id") String id, String rawBody) {
    requireManageRealm();
    Map<String, Object> requestBody = null;
    if (rawBody != null && !rawBody.isBlank()) {
      try {
        requestBody = new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(rawBody,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                });
      } catch (Exception ignored) {
        // ignore malformed body
      }
    }
    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = storage.getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }
    String currentStatus = (String) agentData.get("status");
    if ("expired".equals(currentStatus)) {
      return Response.ok(agentData).build();
    }
    if (!"active".equals(currentStatus)) {
      return Response.status(409)
          .entity(Map.of("error", "invalid_state",
              "message", "Cannot force-expire agent in '" + currentStatus + "' state"))
          .build();
    }
    agentData.put("status", "expired");
    if (requestBody != null && (Boolean.TRUE.equals(requestBody.get("absolute_lifetime_elapsed"))
        || Boolean.TRUE.equals(requestBody.get("exceed_absolute_lifetime")))) {
      agentData.put("absolute_lifetime_elapsed", true);
    }
    if (requestBody != null && Boolean.TRUE.equals(requestBody.get("escalate_capability"))) {
      List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
          .get("agent_capability_grants");
      if (grants != null) {
        Map<String, Object> newGrant = new HashMap<>();
        newGrant.put("capability", "escalated_cap");
        newGrant.put("status", "active");
        newGrant.put("escalated", true);
        grants.add(newGrant);
      }
    }
    storage.putAgent(id, agentData);
    emitAdminEvent("agent-auth/agent/" + id + "/expire", OperationType.ACTION, agentData);
    return Response.ok(agentData).build();
  }

  /**
   * Test-only endpoint that backdates lifecycle-clock timestamps on an agent record without
   * mutating its {@code status}. Lets integration tests simulate session/max/absolute lifetime
   * elapsing so the lazy {@link LifecycleClock} evaluator (called from status/reactivate/execute/
   * introspect) can be exercised without time-travel.
   *
   * <p>
   * Body knobs (all optional):
   *
   * <ul>
   * <li>{@code expires_at_offset_seconds} — set {@code expires_at} to {@code now + offset}; use a
   * negative value to push it into the past.</li>
   * <li>{@code created_at_offset_seconds} — replace {@code created_at} with {@code now + offset};
   * use a negative value to backdate creation.</li>
   * <li>{@code absolute_lifetime_seconds} — store the absolute-lifetime budget so the evaluator can
   * compare it against {@code created_at}.</li>
   * <li>{@code max_lifetime_seconds} — store the max-lifetime budget so the evaluator can compare
   * it against {@code max_lifetime_reset_at}/{@code created_at}.</li>
   * <li>{@code max_lifetime_reset_offset_seconds} — set {@code max_lifetime_reset_at} to
   * {@code now + offset} (epoch millis).</li>
   * </ul>
   */
  @POST
  @Path("agents/{id}/backdate-clocks")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.APPLICATION_JSON)
  public Response backdateAgentClocks(@PathParam("id") String id, String rawBody) {
    requireManageRealm();
    if (!"true".equals(System.getProperty("agent-auth.test-mode"))) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }
    Map<String, Object> requestBody = null;
    if (rawBody != null && !rawBody.isBlank()) {
      try {
        requestBody = new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(rawBody,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                });
      } catch (Exception ignored) {
        // ignore malformed body
      }
    }
    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = storage.getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }

    if (requestBody != null) {
      Long expiresAtOffset = readLong(requestBody, "expires_at_offset_seconds");
      if (expiresAtOffset != null) {
        agentData.put("expires_at", Instant.now().plusSeconds(expiresAtOffset).toString());
      }
      Long createdAtOffset = readLong(requestBody, "created_at_offset_seconds");
      if (createdAtOffset != null) {
        long backdated = System.currentTimeMillis() + createdAtOffset * 1000L;
        // Both representations: keep the ISO string in lock-step for in-memory storage and for
        // any caller that reads `created_at` directly, AND drop the JPA-only override so the
        // storage layer mutates CREATED_AT on this write.
        agentData.put("created_at", Instant.ofEpochMilli(backdated).toString());
        agentData.put("created_at_override_epoch_millis", backdated);
      }
      Long absoluteLifetimeSeconds = readLong(requestBody, "absolute_lifetime_seconds");
      if (absoluteLifetimeSeconds != null) {
        agentData.put("absolute_lifetime_seconds", absoluteLifetimeSeconds);
      }
      Long maxLifetimeSeconds = readLong(requestBody, "max_lifetime_seconds");
      if (maxLifetimeSeconds != null) {
        agentData.put("max_lifetime_seconds", maxLifetimeSeconds);
      }
      Long maxResetOffset = readLong(requestBody, "max_lifetime_reset_offset_seconds");
      if (maxResetOffset != null) {
        agentData.put("max_lifetime_reset_at",
            System.currentTimeMillis() + maxResetOffset * 1000L);
      }
    }

    storage.putAgent(id, agentData);
    emitAdminEvent("agent-auth/agent/" + id + "/backdate-clocks", OperationType.ACTION, agentData);
    return Response.ok(agentData).build();
  }

  private static Long readLong(Map<String, Object> body, String key) {
    Object value = body.get(key);
    if (value instanceof Number n) {
      return n.longValue();
    }
    if (value instanceof String s && !s.isBlank()) {
      try {
        return Long.parseLong(s.trim());
      } catch (NumberFormatException ignored) {
        return null;
      }
    }
    return null;
  }

  @POST
  @Path("agents/{id}/reject")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response rejectAgent(@PathParam("id") String id, String rawBody) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = storage.getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }

    String currentStatus = (String) agentData.get("status");
    if ("rejected".equals(currentStatus)) {
      return Response.ok(agentData).build();
    }
    if (!"pending".equals(currentStatus)) {
      return Response.status(409)
          .entity(Map.of("error", "invalid_state",
              "message", "Cannot reject agent in '" + currentStatus + "' state"))
          .build();
    }

    String reason = "Approval denied";
    if (rawBody != null && !rawBody.isBlank()) {
      try {
        Map<String, Object> requestBody = new com.fasterxml.jackson.databind.ObjectMapper()
            .readValue(rawBody,
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                });
        Object requestedReason = requestBody.get("reason");
        if (requestedReason instanceof String && !((String) requestedReason).isBlank()) {
          reason = (String) requestedReason;
        }
      } catch (Exception ignored) {
        // ignore malformed body
      }
    }

    agentData.put("status", "rejected");
    agentData.put("rejection_reason", reason);
    agentData.put("updated_at", Instant.now().toString());
    List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
        .get("agent_capability_grants");
    if (grants != null) {
      for (Map<String, Object> grant : grants) {
        if ("pending".equals(grant.get("status"))) {
          grant.put("status", "denied");
          grant.put("reason", reason);
          grant.remove("status_url");
          // Discard the agent's pending request scope on denial so a denied entry never
          // carries leftover request metadata into storage or future responses.
          grant.remove("requested_constraints");
        }
      }
    }
    storage.putAgent(id, agentData);
    emitAdminEvent("agent-auth/agent/" + id + "/reject", OperationType.ACTION, agentData);
    return Response.ok(agentData).build();
  }

  @POST
  @Path("agents/{id}/capabilities/{capability}/approve")
  @Consumes(MediaType.WILDCARD)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response approveCapability(@PathParam("id") String id,
      @PathParam("capability") String capability) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = storage.getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }

    Map<String, Object> registeredCap = storage.getCapability(capability);
    if (registeredCap == null) {
      return Response.status(404).entity(Map.of("error", "capability_not_found")).build();
    }

    // Audit 05 P1: terminal agent states (claimed/revoked/rejected) are immutable per AAP §§2.6,
    // 2.10. Approving a grant on such an agent would resurrect authority that the spec already
    // sealed off, so refuse before mutating anything.
    String agentStatus = (String) agentData.get("status");
    if ("claimed".equals(agentStatus) || "revoked".equals(agentStatus)
        || "rejected".equals(agentStatus)) {
      return Response.status(409)
          .entity(Map.of("error", "invalid_state",
              "message", "Cannot approve grant on agent in '" + agentStatus + "' state"))
          .build();
    }

    List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
        .get("agent_capability_grants");
    if (grants == null) {
      return Response.status(404).entity(Map.of("error", "grant_not_found")).build();
    }

    Map<String, Object> targetGrant = null;
    for (Map<String, Object> grant : grants) {
      if (capability.equals(grant.get("capability"))) {
        targetGrant = grant;
        break;
      }
    }
    if (targetGrant == null) {
      return Response.status(404).entity(Map.of("error", "grant_not_found")).build();
    }

    // Audit 05 P1: only pending grants may be promoted to active. Already-active grants are
    // returned idempotently so retries (network blips, double-clicks) don't fail. Anything else —
    // denied, revoked, etc. — is terminal and must not be silently flipped to active.
    String grantStatus = (String) targetGrant.get("status");
    if ("active".equals(grantStatus)) {
      return Response.ok(targetGrant).build();
    }
    if (!"pending".equals(grantStatus)) {
      return Response.status(409)
          .entity(Map.of("error", "invalid_state",
              "message", "Cannot approve grant in '" + grantStatus + "' state"))
          .build();
    }

    // AAP-ADMIN-001: an admin-approved grant on a delegated agent under a host with no owning
    // user has no entitlement to gate against — and after approval, the agent itself would
    // inherit no user_id. Require the host be linked first so admin approval doesn't mint
    // unowned authority. Autonomous agents bring their own user_id (set at register/claim
    // time) so the host-side requirement only applies to delegated mode.
    String agentMode = (String) agentData.get("mode");
    String agentHostId = (String) agentData.get("host_id");
    Map<String, Object> hostForOwnership = agentHostId == null
        ? null
        : storage.getHost(agentHostId);
    String hostUserId = hostForOwnership == null
        ? null
        : (String) hostForOwnership.get("user_id");
    String agentUserIdExisting = (String) agentData.get("user_id");
    if ("delegated".equals(agentMode)
        && (hostUserId == null || hostUserId.isBlank())
        && (agentUserIdExisting == null || agentUserIdExisting.isBlank())) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_state",
              "message",
              "Host must be linked to a user before approving delegated grants;"
                  + " POST /hosts/{id}/link or pre-register with user_id/client_id first"))
          .build();
    }

    // AAP-ADMIN-002: mirror the user-approval gate at AgentAuthRealmResourceProvider#3270.
    // Resolve the effective user (agent.user_id wins, then host.user_id) and run the same
    // org/role entitlement check that /verify/approve uses. When the cap is no longer in the
    // catalog, or the user can't grant under the cap's gate, flip to denied(reason=
    // insufficient_authority) instead of activating — same shape as the user-approval flow.
    String effectiveUserId = (agentUserIdExisting != null && !agentUserIdExisting.isBlank())
        ? agentUserIdExisting
        : hostUserId;
    AgentAuthRealmResourceProvider.UserEntitlement approverEntitlement = AgentAuthRealmResourceProvider
        .loadUserEntitlement(session, effectiveUserId);
    if (!AgentAuthRealmResourceProvider.userEntitlementAllows(registeredCap,
        approverEntitlement)) {
      targetGrant.put("status", "denied");
      targetGrant.put("reason", "insufficient_authority");
      targetGrant.remove("status_url");
      targetGrant.remove("requested_constraints");
      agentData.put("updated_at", Instant.now().toString());
      storage.putAgent(id, agentData);
      emitAdminEvent("agent-auth/agent/" + id + "/capability/" + capability + "/approve",
          OperationType.ACTION, targetGrant);
      return Response.ok(targetGrant).build();
    }

    boolean wasPending = "pending".equals(targetGrant.get("status"));
    targetGrant.put("status", "active");
    targetGrant.put("description", registeredCap.get("description"));
    if (registeredCap.containsKey("input")) {
      targetGrant.put("input", registeredCap.get("input"));
    }
    if (registeredCap.containsKey("output")) {
      targetGrant.put("output", registeredCap.get("output"));
    }
    targetGrant.put("granted_by", approverUserId());
    targetGrant.remove("status_url");
    // §2.13: promote the agent's originally-requested scope from the pending stash into
    // `constraints`. The pending grant carries `requested_constraints`; admin approval — like
    // user approval at /verify/approve — endorses that scope without redeclaring it. Dropping
    // the stash here would widen the grant beyond what the agent ever asked for.
    Object stashedConstraints = targetGrant.remove("requested_constraints");
    if (stashedConstraints instanceof Map<?, ?>) {
      targetGrant.put("constraints", stashedConstraints);
    }

    boolean hasPendingGrant = false;
    for (Map<String, Object> grant : grants) {
      if ("pending".equals(grant.get("status"))) {
        hasPendingGrant = true;
        break;
      }
    }
    if (!hasPendingGrant && "pending".equals(agentData.get("status"))) {
      agentData.put("status", "active");
      agentData.put("activated_at", Instant.now().toString());
      agentData.remove("approval");
    }
    // AAP-ADMIN-001: stamp agent.user_id from host.user_id so a delegated agent activated by
    // admin approval ends up with the same owning-user binding it would have via the user
    // approval flow at /verify/approve. `granted_by` stays as the approver/admin id —
    // distinct field, distinct purpose (audit/trace, per §3.3.1).
    if ("delegated".equals(agentMode)
        && (agentUserIdExisting == null || agentUserIdExisting.isBlank())
        && hostUserId != null && !hostUserId.isBlank()) {
      agentData.put("user_id", hostUserId);
    }
    agentData.put("updated_at", Instant.now().toString());
    storage.putAgent(id, agentData);

    // §2.8 / §2.11 host activation + §3.1 TOFU. Admin grant approval is one of the
    // auto-approval pathways: it carries the same human-in-the-loop semantics as
    // /verify/approve and so should activate a pending host and append the cap to defaults.
    if (wasPending) {
      String hostId = (String) agentData.get("host_id");
      if (hostId != null) {
        Map<String, Object> hostData = storage.getHost(hostId);
        if (hostData != null) {
          boolean dirty = false;
          if ("pending".equals(hostData.get("status"))) {
            hostData.put("status", "active");
            hostData.put("activated_at", Instant.now().toString());
            dirty = true;
          }
          List<String> existing = readHostDefaultCapabilities(hostData);
          if (!existing.contains(capability)) {
            existing.add(capability);
            hostData.put("default_capabilities", existing);
            dirty = true;
          }
          if (dirty) {
            hostData.put("updated_at", Instant.now().toString());
            storage.putHost(hostId, hostData);
          }
        }
      }
    }

    emitAdminEvent("agent-auth/agent/" + id + "/capability/" + capability + "/approve",
        OperationType.ACTION, targetGrant);
    return Response.ok(targetGrant).build();
  }

  @SuppressWarnings("unchecked")
  private static List<String> readHostDefaultCapabilities(Map<String, Object> hostData) {
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

  @POST
  @Path("hosts")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response preRegisterHost(Map<String, Object> requestBody) {
    requireManageRealm();
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    Object rawKey = requestBody.get("host_public_key");
    if (!(rawKey instanceof Map)) {
      return Response.status(400).entity(Map.of("error", "invalid_request", "message",
          "Missing host_public_key")).build();
    }
    Map<String, Object> hostPublicKeyMap = (Map<String, Object>) rawKey;

    HostKeyParseResult parsed = parseEd25519HostKeyThumbprint(hostPublicKeyMap);
    if (parsed.errorResponse() != null) {
      return parsed.errorResponse();
    }
    String hostId = parsed.thumbprint();

    AgentAuthStorage storage = storage();
    if (storage.getHost(hostId) != null) {
      return Response.status(409).entity(Map.of("error", "host_exists", "message",
          "Host already registered")).build();
    }

    String nowTs = Instant.now().toString();
    Map<String, Object> hostData = new HashMap<>();
    hostData.put("host_id", hostId);
    hostData.put("public_key", hostPublicKeyMap);
    hostData.put("created_at", nowTs);
    hostData.put("updated_at", nowTs);

    Object name = requestBody.get("name");
    if (name instanceof String && !((String) name).isBlank()) {
      hostData.put("name", name);
    }
    Object description = requestBody.get("description");
    if (description instanceof String && !((String) description).isBlank()) {
      hostData.put("description", description);
    }

    // AAP-ADMIN-001: a pre-registered host without an owning user is unsafe — delegated agents
    // registered under it would have no `user_id` to gate against, and the existing approve
    // flow can't bind one (the agent is auto-active because the host is active). Three branches:
    // (a) `client_id` present → SA-as-host pattern, host.user_id := SA user, status active.
    // (b) `user_id` present and resolves to a realm user → host pre-bound, status active.
    // (c) neither → status pending. The standard /verify/approve flow on the first delegated
    // agent under this host will both link the user and activate the host.
    // This closes the "active-but-unowned" hole (admin-created host with status=active and no
    // user_id) that previously let a delegated agent accept any approver without entitlement
    // checks downstream.
    Object rawClientId = requestBody.get("client_id");
    Object rawUserId = requestBody.get("user_id");
    boolean hasClientId = rawClientId instanceof String && !((String) rawClientId).isBlank();
    boolean hasUserId = rawUserId instanceof String && !((String) rawUserId).isBlank();
    if (hasClientId && hasUserId) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "Specify at most one of client_id or user_id"))
          .build();
    }
    // Phase 5 SA-as-host pattern: optionally resolve a confidential client's service-account
    // user as the host's owner. The recommended pattern (see TODO.md) is one SA per
    // confidential client; the operator pre-registers the client with serviceAccountsEnabled
    // and passes the client_id here so the host's user_id is set up-front, skipping the
    // post-claim /verify/approve flow that delegated agents normally need.
    if (hasClientId) {
      String clientId = (String) rawClientId;
      RealmModel realm = session.getContext().getRealm();
      org.keycloak.models.ClientModel client = realm == null
          ? null
          : realm.getClientByClientId(clientId);
      if (client == null) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request",
                "message", "client_id does not resolve to a realm client"))
            .build();
      }
      if (!client.isServiceAccountsEnabled()) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request",
                "message", "client_id does not have service accounts enabled"))
            .build();
      }
      org.keycloak.models.UserModel saUser = session.users().getServiceAccount(client);
      if (saUser == null) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request",
                "message", "service account user not provisioned for client"))
            .build();
      }
      hostData.put("user_id", saUser.getId());
      hostData.put("service_account_client_id", clientId);
      hostData.put("status", "active");
      hostData.put("activated_at", nowTs);
    } else if (hasUserId) {
      String userId = (String) rawUserId;
      RealmModel realm = session.getContext().getRealm();
      if (realm == null || session.users().getUserById(realm, userId) == null) {
        return Response.status(400)
            .entity(Map.of("error", "invalid_request",
                "message", "user_id does not resolve to a realm user"))
            .build();
      }
      hostData.put("user_id", userId);
      hostData.put("status", "active");
      hostData.put("activated_at", nowTs);
    } else {
      // No user binding supplied: stage as pending. The first /verify/approve under this host
      // links a real user and activates the host (mirrors the dynamic-registration path at
      // §2.8 / §2.11), so a delegated agent never operates without an owning user.
      hostData.put("status", "pending");
    }

    storage.putHost(hostId, hostData);
    emitAdminEvent("agent-auth/host/" + hostId, OperationType.CREATE, hostData);
    return Response.status(201).entity(hostData).build();
  }

  @GET
  @Path("hosts/{id}")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getHost(@PathParam("id") String id) {
    requireManageRealm();
    Map<String, Object> hostData = storage().getHost(id);
    if (hostData == null) {
      return Response.status(404).entity(Map.of("error", "host_not_found",
          "message", "Host not found")).build();
    }
    return Response.ok(hostData).build();
  }

  @GET
  @Path("agents/{id}")
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response getAgent(@PathParam("id") String id) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    Map<String, Object> agentData = storage.getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "agent_not_found",
          "message", "Agent not found")).build();
    }
    // Audit 05 P2: when a capability is deleted from the registry, runtime paths fail closed
    // (execute / introspect / reactivate skip the orphan grant) but the stored grant blob is
    // intentionally left intact. Without this read-time decoration, GET /agents/{id} would still
    // advertise the orphan grant as `active`, which is misleading for operators reasoning about
    // what authority the agent actually carries. Decorate without mutating the stored record.
    Object rawGrants = agentData.get("agent_capability_grants");
    if (rawGrants instanceof List<?>) {
      List<Map<String, Object>> grants = (List<Map<String, Object>>) rawGrants;
      List<Map<String, Object>> decorated = decorateGrantsWithInoperative(grants, storage);
      Map<String, Object> copy = new HashMap<>(agentData);
      copy.put("agent_capability_grants", decorated);
      return Response.ok(copy).build();
    }
    return Response.ok(agentData).build();
  }

  /**
   * Phase 3 of the multi-tenant authz plan: returns the {@code AGENT_AUTH_AGENT_GRANT} secondary-
   * index rows for an agent, distinct from the JSON-blob grants in {@link #getAgent}. Used to
   * verify the sync-on-write index stays consistent with the blob; Phase 4's eager cascade and
   * future Phase 6 read-path swaps will query this table directly.
   */
  @GET
  @Path("agents/{id}/grants")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getAgentGrants(@PathParam("id") String id) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    List<Map<String, Object>> rows = storage.findGrantsByAgent(id);
    // Audit 05 P2: same read-time decoration as getAgent — flag grants whose capability has been
    // removed from the registry so admin tooling doesn't display them as live authority. Runtime
    // paths already fail closed for these orphan grants; this is purely an operator-facing hint.
    List<Map<String, Object>> decorated = decorateGrantsWithInoperative(rows, storage);
    return Response.ok(Map.of("grants", decorated)).build();
  }

  /**
   * Audit 05 P2 read-time decoration: returns a fresh list of grant maps with {@code inoperative:
   * true} added to any grant whose capability is no longer present in the registry. The stored
   * grant blob is never mutated — capability deletion deliberately leaves grants in place so an
   * operator who re-registers the cap (or reads the audit trail) can still see what authority an
   * agent once held. Runtime authorization paths (execute / introspect / reactivate) already fail
   * closed when the cap is missing, so the {@code inoperative} hint is purely cosmetic for
   * admin-facing GET endpoints.
   */
  private static List<Map<String, Object>> decorateGrantsWithInoperative(
      List<Map<String, Object>> grants, AgentAuthStorage storage) {
    List<Map<String, Object>> out = new ArrayList<>(grants.size());
    for (Map<String, Object> grant : grants) {
      Map<String, Object> copy = new HashMap<>(grant);
      Object capName = grant.get("capability");
      if (capName instanceof String && storage.getCapability((String) capName) == null) {
        copy.put("inoperative", true);
      }
      out.add(copy);
    }
    return out;
  }

  /**
   * AAP §7.1: "Servers SHOULD periodically clean up agents that remain in pending state beyond a
   * server-defined threshold ... Cleaned-up pending agents are deleted, not revoked — they never
   * became active." This endpoint gives operators a manual trigger for the sweep (the extension
   * also schedules an automatic hourly sweep once per JVM). Returns the number of agents removed.
   */
  @POST
  @Path("pending-agents/cleanup")
  @Produces(MediaType.APPLICATION_JSON)
  public Response cleanupPendingAgents(
      @jakarta.ws.rs.QueryParam("olderThanSeconds") Long olderThanSeconds) {
    requireManageRealm();
    long thresholdSec = olderThanSeconds == null
        ? PendingAgentCleanup.DEFAULT_THRESHOLD_SECONDS
        : Math.max(0L, olderThanSeconds);
    long thresholdMs = System.currentTimeMillis() - (thresholdSec * 1000L);
    AgentAuthStorage storage = storage();
    int removedAgents = storage.deletePendingAgentsOlderThan(thresholdMs);
    // Cascade: pending hosts whose only agents we just deleted (or that were already orphaned)
    // are reaped in the same transaction. Spec doesn't mandate this — §7.1 cleanup is
    // agent-only — but pending hosts otherwise accumulate from abandoned dynamic
    // registrations. The "no remaining agents" filter inside the storage method preserves the
    // user's retry window: a still-young pending agent under a pending host keeps the host
    // alive.
    int removedHosts = storage.deleteOrphanedPendingHostsOlderThan(thresholdMs);
    return Response.ok(Map.of(
        "removed", removedAgents + removedHosts,
        "removed_agents", removedAgents,
        "removed_hosts", removedHosts,
        "threshold_seconds", thresholdSec))
        .build();
  }

  /**
   * Links a host to a Keycloak user (AAP §2.9). On link, autonomous agents under the host are
   * claimed per §2.10 and delegated agents inherit the host's {@code user_id} per §3.2.
   */
  @POST
  @Path("hosts/{id}/link")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response linkHost(@PathParam("id") String hostId, Map<String, Object> requestBody) {
    requireManageRealm();
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }
    Object rawUserId = requestBody.get("user_id");
    if (!(rawUserId instanceof String) || ((String) rawUserId).isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing user_id")).build();
    }
    String userId = (String) rawUserId;

    AgentAuthStorage storage = storage();
    Map<String, Object> hostData = storage.getHost(hostId);
    if (hostData == null) {
      return Response.status(404)
          .entity(Map.of("error", "host_not_found", "message", "Host not found")).build();
    }

    RealmModel realm = session.getContext().getRealm();
    if (realm == null || session.users().getUserById(realm, userId) == null) {
      return Response.status(404)
          .entity(Map.of("error", "user_not_found", "message", "User not found")).build();
    }

    Object existingUserId = hostData.get("user_id");
    if (existingUserId != null && !userId.equals(existingUserId)) {
      return Response.status(409)
          .entity(Map.of("error", "host_already_linked",
              "message", "Host is already linked to a different user"))
          .build();
    }

    String nowTs = Instant.now().toString();
    hostData.put("user_id", userId);
    hostData.put("updated_at", nowTs);
    storage.putHost(hostId, hostData);

    // Cascade to agents under this host.
    for (Map<String, Object> agentData : storage.findAgentsByHost(hostId)) {
      String agentId = (String) agentData.get("agent_id");
      String mode = (String) agentData.get("mode");
      String status = (String) agentData.get("status");
      boolean terminal = "claimed".equals(status) || "revoked".equals(status)
          || "rejected".equals(status);
      if ("autonomous".equals(mode) && !terminal) {
        // §2.10: claim — status="claimed", revoke grants, attribute to user.
        agentData.put("status", "claimed");
        agentData.put("user_id", userId);
        agentData.put("updated_at", nowTs);
        List<Map<String, Object>> grants = (List<Map<String, Object>>) agentData
            .get("agent_capability_grants");
        if (grants != null) {
          for (Map<String, Object> grant : grants) {
            if (!"revoked".equals(grant.get("status"))) {
              grant.put("status", "revoked");
            }
          }
        }
        storage.putAgent(agentId, agentData);
      } else if ("delegated".equals(mode)) {
        // §3.2: agent.user_id is set from host.user_id. Propagate unchanged status.
        agentData.put("user_id", userId);
        agentData.put("updated_at", nowTs);
        storage.putAgent(agentId, agentData);
      }
    }

    emitAdminEvent("agent-auth/host/" + hostId + "/link", OperationType.ACTION, hostData);
    return Response.ok(hostData).build();
  }

  /**
   * Unlinks a host. Per AAP §2.9, all delegated agents under the host MUST be revoked — their
   * authority derived from the now-removed user linkage. Autonomous agents (already {@code claimed}
   * by the link cascade) are terminal and left alone.
   */
  @DELETE
  @Path("hosts/{id}/link")
  @Produces(MediaType.APPLICATION_JSON)
  public Response unlinkHost(@PathParam("id") String hostId) {
    requireManageRealm();
    AgentAuthStorage storage = storage();
    Map<String, Object> hostData = storage.getHost(hostId);
    if (hostData == null) {
      return Response.status(404)
          .entity(Map.of("error", "host_not_found", "message", "Host not found")).build();
    }

    Object existingUserId = hostData.get("user_id");
    if (existingUserId != null) {
      String nowTs = Instant.now().toString();
      for (Map<String, Object> agentData : storage.findAgentsByHost(hostId)) {
        String agentId = (String) agentData.get("agent_id");
        String mode = (String) agentData.get("mode");
        String status = (String) agentData.get("status");
        if ("delegated".equals(mode) && !"revoked".equals(status) && !"rejected".equals(status)) {
          agentData.put("status", "revoked");
          agentData.put("updated_at", nowTs);
          storage.putAgent(agentId, agentData);
        }
      }
      hostData.remove("user_id");
      hostData.put("updated_at", nowTs);
      storage.putHost(hostId, hostData);
    }

    emitAdminEvent("agent-auth/host/" + hostId + "/unlink", OperationType.ACTION, hostData);
    return Response.noContent().build();
  }

  private void requireManageRealm() {
    if (auth != null) {
      auth.realm().requireManageRealm();
    }
  }

  /**
   * Org-scoped SA-host pre-registration. Mirrors {@link #preRegisterHost} but path-scoped to a
   * specific org and gated by {@link #requireOrgAdmin}, so org admins can self-serve SA-host
   * provisioning without going through realm-admin every time. Differences vs the realm-admin
   * endpoint:
   *
   * <ul>
   * <li>{@code client_id} is required (the org-scoped path implies SA-as-host).</li>
   * <li>The resolved service-account user must already be a member of the path's org. Org admins
   * have {@code manage-organization}, so they can add the SA user to their own org via standard KC
   * org-membership APIs; the existing Phase 4 {@code handleOrgMemberLeave} listener cascades grant
   * revocations for free if the SA is later removed.</li>
   * </ul>
   *
   * The realm-admin {@link #preRegisterHost} stays available and unchanged for headless setups
   * where the SA isn't (yet) part of any org.
   */
  @POST
  @Path("organizations/{orgId}/hosts")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response registerOrgHost(@PathParam("orgId") String orgId,
      Map<String, Object> requestBody) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    org.keycloak.models.OrganizationModel org = requireOrgAdmin(orgId);
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    Object rawKey = requestBody.get("host_public_key");
    if (!(rawKey instanceof Map)) {
      return Response.status(400).entity(Map.of("error", "invalid_request", "message",
          "Missing host_public_key")).build();
    }
    Map<String, Object> hostPublicKeyMap = (Map<String, Object>) rawKey;

    Object rawClientId = requestBody.get("client_id");
    if (!(rawClientId instanceof String) || ((String) rawClientId).isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "client_id is required for org-scoped host registration"))
          .build();
    }
    String clientId = (String) rawClientId;

    HostKeyParseResult parsed = parseEd25519HostKeyThumbprint(hostPublicKeyMap);
    if (parsed.errorResponse() != null) {
      return parsed.errorResponse();
    }
    String hostId = parsed.thumbprint();

    RealmModel realm = session.getContext().getRealm();
    org.keycloak.models.ClientModel client = realm == null
        ? null
        : realm.getClientByClientId(clientId);
    if (client == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "client_id does not resolve to a realm client"))
          .build();
    }
    if (!client.isServiceAccountsEnabled()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "client_id does not have service accounts enabled"))
          .build();
    }
    org.keycloak.models.UserModel saUser = session.users().getServiceAccount(client);
    if (saUser == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "service account user not provisioned for client"))
          .build();
    }

    // SA-belongs-to-org gate: the SA must already be a member of the path's org. Without this,
    // an org admin could bind a host to any client's SA in the realm — including SAs an
    // unrelated tenant operates.
    org.keycloak.organization.OrganizationProvider orgProvider = session.getProvider(
        org.keycloak.organization.OrganizationProvider.class);
    if (!orgProvider.isMember(org, saUser)) {
      return Response.status(400)
          .entity(Map.of("error", "sa_not_in_org",
              "message",
              "Service-account user is not a member of the target organization"))
          .build();
    }

    AgentAuthStorage storage = storage();
    if (storage.getHost(hostId) != null) {
      return Response.status(409).entity(Map.of("error", "host_exists", "message",
          "Host already registered")).build();
    }

    String nowTs = Instant.now().toString();
    Map<String, Object> hostData = new HashMap<>();
    hostData.put("host_id", hostId);
    hostData.put("public_key", hostPublicKeyMap);
    hostData.put("status", "active");
    hostData.put("created_at", nowTs);
    hostData.put("updated_at", nowTs);
    hostData.put("user_id", saUser.getId());
    hostData.put("service_account_client_id", clientId);

    Object name = requestBody.get("name");
    if (name instanceof String && !((String) name).isBlank()) {
      hostData.put("name", name);
    }
    Object description = requestBody.get("description");
    if (description instanceof String && !((String) description).isBlank()) {
      hostData.put("description", description);
    }

    storage.putHost(hostId, hostData);
    emitAdminEvent("agent-auth/organization/" + orgId + "/host/" + hostId,
        OperationType.CREATE, hostData);
    return Response.status(201).entity(hostData).build();
  }

  // --- Org-self-serve agent environments ---
  // Privileged op: creating a confidential client + binding its SA to the org + pre-registering
  // the host, all from a manage-organization caller. The client is locked down structurally so
  // org admins can't repurpose it for OIDC flows or escalate privilege; clients are tagged so
  // cleanup and audit are queryable.

  /** Hard cap on managed clients per org. Tunable later if a real limit emerges. */
  private static final int MAX_MANAGED_CLIENTS_PER_ORG = 50;

  private static final String MANAGED_ATTR = "agent_auth_managed";
  private static final String MANAGED_ORG_ATTR = "agent_auth_organization_id";

  /**
   * Org-self-serve agent environment provisioning. Creates a locked-down confidential client with a
   * service-account user, adds the SA to the path's org, and pre-registers the host — all under a
   * single {@code manage-organization} call. Returns the {@code client_secret} once; it's not
   * retrievable afterward (rotate by deleting + recreating).
   *
   * <p>
   * Lockdown: the created client has all OIDC flows disabled and no redirect URIs. The only thing
   * it can do is mint client_credentials tokens for its SA user, which is exactly what the workload
   * needs to operate as the host owner. These flags are hard-coded and cannot be overridden via
   * this endpoint's body — only {@code name} and {@code host_public_key} are accepted.
   *
   * <p>
   * Audit/cleanup: every managed client is tagged with {@code agent_auth_managed=true} and
   * {@code agent_auth_organization_id=<orgId>}. The DELETE counterpart uses these tags to scope the
   * operation; KC's native admin can still mutate these clients out-of-band, but the extension's
   * own surface won't.
   */
  @POST
  @Path("organizations/{orgId}/agent-environments")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response createOrgAgentEnvironment(@PathParam("orgId") String orgId,
      Map<String, Object> requestBody) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    org.keycloak.models.OrganizationModel targetOrg = requireOrgAdmin(orgId);

    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }
    Object rawKey = requestBody.get("host_public_key");
    if (!(rawKey instanceof Map)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing host_public_key"))
          .build();
    }
    Map<String, Object> hostPublicKeyMap = (Map<String, Object>) rawKey;

    HostKeyParseResult parsed = parseEd25519HostKeyThumbprint(hostPublicKeyMap);
    if (parsed.errorResponse() != null) {
      return parsed.errorResponse();
    }
    String hostId = parsed.thumbprint();

    AgentAuthStorage storage = storage();
    if (storage.getHost(hostId) != null) {
      return Response.status(409)
          .entity(Map.of("error", "host_exists", "message", "Host already registered")).build();
    }

    RealmModel realm = session.getContext().getRealm();
    long managedCount = realm.getClientsStream()
        .filter(c -> "true".equals(c.getAttribute(MANAGED_ATTR))
            && orgId.equals(c.getAttribute(MANAGED_ORG_ATTR)))
        .count();
    if (managedCount >= MAX_MANAGED_CLIENTS_PER_ORG) {
      return Response.status(429)
          .entity(Map.of("error", "quota_exceeded",
              "message", "Org has reached the managed-environment limit ("
                  + MAX_MANAGED_CLIENTS_PER_ORG + ")"))
          .build();
    }

    Object rawName = requestBody.get("name");
    String envName = (rawName instanceof String && !((String) rawName).isBlank())
        ? (String) rawName
        : null;

    String clientIdSuffix = java.util.UUID.randomUUID().toString().replace("-", "").substring(0,
        12);
    String clientId = "agentauth-" + clientIdSuffix;
    String clientSecret = generateClientSecret();

    org.keycloak.models.ClientModel client;
    try {
      org.keycloak.representations.idm.ClientRepresentation rep = new org.keycloak.representations.idm.ClientRepresentation();
      rep.setClientId(clientId);
      rep.setEnabled(true);
      rep.setPublicClient(false);
      rep.setServiceAccountsEnabled(true);
      rep.setStandardFlowEnabled(false);
      rep.setImplicitFlowEnabled(false);
      rep.setDirectAccessGrantsEnabled(false);
      rep.setAuthorizationServicesEnabled(false);
      rep.setProtocol("openid-connect");
      rep.setSecret(clientSecret);
      rep.setRedirectUris(List.of());
      rep.setRootUrl("");
      rep.setBaseUrl("");
      Map<String, String> attrs = new HashMap<>();
      attrs.put(MANAGED_ATTR, "true");
      attrs.put(MANAGED_ORG_ATTR, orgId);
      rep.setAttributes(attrs);
      if (envName != null) {
        rep.setName(envName);
      }
      client = org.keycloak.models.utils.RepresentationToModel.createClient(session, realm, rep);
      // Explicit SA provisioning: createClient() persists serviceAccountsEnabled=true on the
      // ClientModel but doesn't auto-create the SA user; ClientManager.enableServiceAccount() is
      // what actually provisions service-account-<clientId>.
      new org.keycloak.services.managers.ClientManager(
          new org.keycloak.services.managers.RealmManager(session)).enableServiceAccount(client);
    } catch (Exception e) {
      return Response.status(500)
          .entity(Map.of("error", "client_creation_failed", "message", e.getMessage()))
          .build();
    }

    try {
      org.keycloak.models.UserModel saUser = session.users().getServiceAccount(client);
      if (saUser == null) {
        throw new IllegalStateException(
            "Service-account user not auto-provisioned by Keycloak");
      }
      org.keycloak.organization.OrganizationProvider orgProvider = session.getProvider(
          org.keycloak.organization.OrganizationProvider.class);
      if (!orgProvider.isMember(targetOrg, saUser)) {
        orgProvider.addMember(targetOrg, saUser);
      }

      String nowTs = Instant.now().toString();
      Map<String, Object> hostData = new HashMap<>();
      hostData.put("host_id", hostId);
      hostData.put("public_key", hostPublicKeyMap);
      hostData.put("status", "active");
      hostData.put("created_at", nowTs);
      hostData.put("updated_at", nowTs);
      hostData.put("user_id", saUser.getId());
      hostData.put("service_account_client_id", clientId);
      if (envName != null) {
        hostData.put("name", envName);
      }
      storage.putHost(hostId, hostData);

      // Audit event deliberately omits client_secret — events are persisted, secret must not be.
      emitAdminEvent("agent-auth/organization/" + orgId + "/agent-environment/" + clientId,
          OperationType.CREATE, Map.of(
              "client_id", clientId,
              "host_id", hostId,
              "service_account_user_id", saUser.getId(),
              "organization_id", orgId));

      Map<String, Object> response = new HashMap<>();
      response.put("client_id", clientId);
      response.put("client_secret", clientSecret);
      response.put("host_id", hostId);
      response.put("service_account_user_id", saUser.getId());
      response.put("organization_id", orgId);
      if (envName != null) {
        response.put("name", envName);
      }
      return Response.status(201).entity(response).build();
    } catch (Exception e) {
      // Best-effort rollback — orphaned managed clients are queryable via the tag attributes,
      // so a janitor can clean them up later if rollback also fails.
      try {
        realm.removeClient(client.getId());
      } catch (Exception ignored) {
        // swallow; the partially-created client will surface on next list/audit
      }
      return Response.status(500)
          .entity(Map.of("error", "environment_setup_failed", "message", e.getMessage()))
          .build();
    }
  }

  /**
   * List managed agent environments for an organization. Returns the tagged clients owned by the
   * path's org with their resolved SA user and bound host. {@code client_secret} is intentionally
   * never included — secrets are returned exactly once at creation and aren't retrievable later;
   * the right rotation path is delete + recreate.
   */
  @GET
  @Path("organizations/{orgId}/agent-environments")
  @Produces(MediaType.APPLICATION_JSON)
  public Response listOrgAgentEnvironments(@PathParam("orgId") String orgId) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);

    RealmModel realm = session.getContext().getRealm();
    AgentAuthStorage storage = storage();
    List<Map<String, Object>> envs = new ArrayList<>();
    realm.getClientsStream()
        .filter(c -> "true".equals(c.getAttribute(MANAGED_ATTR))
            && orgId.equals(c.getAttribute(MANAGED_ORG_ATTR)))
        .forEach(c -> {
          Map<String, Object> env = new HashMap<>();
          env.put("client_id", c.getClientId());
          env.put("organization_id", orgId);
          if (c.getName() != null && !c.getName().isBlank()) {
            env.put("name", c.getName());
          }
          org.keycloak.models.UserModel saUser = session.users().getServiceAccount(c);
          if (saUser != null) {
            env.put("service_account_user_id", saUser.getId());
            // Resolve the host by SA owner. There should be exactly one managed host per env;
            // if there's none (e.g. host was admin-revoked but client wasn't deleted) we still
            // return the env, just without a host_id — surfaces the inconsistency for ops.
            for (Map<String, Object> host : storage.findHostsByUser(saUser.getId())) {
              if (c.getClientId().equals(host.get("service_account_client_id"))) {
                env.put("host_id", host.get("host_id"));
                env.put("host_status", host.get("status"));
                break;
              }
            }
          }
          envs.add(env);
        });

    return Response.ok(Map.of("agent_environments", envs)).build();
  }

  /**
   * Delete a managed agent environment: removes the KC client, which cascades to the SA user, which
   * fires {@code UserRemovedEvent} and triggers
   * {@link AgentAuthUserEventListenerProviderFactory#handleUserRemoved} to revoke the host and all
   * agents under it.
   *
   * <p>
   * Returns 404 for clients that aren't tagged as managed by this org (don't leak existence of
   * unrelated clients to org admins).
   */
  @DELETE
  @Path("organizations/{orgId}/agent-environments/{clientId}")
  public Response deleteOrgAgentEnvironment(@PathParam("orgId") String orgId,
      @PathParam("clientId") String clientId) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);

    RealmModel realm = session.getContext().getRealm();
    org.keycloak.models.ClientModel client = realm.getClientByClientId(clientId);
    if (client == null
        || !"true".equals(client.getAttribute(MANAGED_ATTR))
        || !orgId.equals(client.getAttribute(MANAGED_ORG_ATTR))) {
      return Response.status(404)
          .entity(Map.of("error", "environment_not_found",
              "message", "Managed environment not found in this organization"))
          .build();
    }

    // Explicit revocation: don't rely on the UserRemovedEvent cascade through KC's in-process
    // client/SA deletion — its eventing behavior in this code path is brittle. Find the host
    // by service_account_client_id and revoke it directly; the user-removed listener still acts
    // as a safety net if the timing differs.
    org.keycloak.models.UserModel saUser = session.users().getServiceAccount(client);
    if (saUser != null) {
      String saUserId = saUser.getId();
      String nowTs = Instant.now().toString();
      AgentAuthStorage storage = storage();
      for (Map<String, Object> hostData : storage.findHostsByUser(saUserId)) {
        String hostId = (String) hostData.get("host_id");
        if (hostId == null) {
          continue;
        }
        String status = (String) hostData.get("status");
        if ("revoked".equals(status) || "rejected".equals(status) || "claimed".equals(status)) {
          continue;
        }
        // Revoke any non-terminal agents under this host first, then the host itself.
        for (Map<String, Object> agentData : storage.findAgentsByHost(hostId)) {
          String agentId = (String) agentData.get("agent_id");
          String agentStatus = (String) agentData.get("status");
          if (agentId == null
              || "revoked".equals(agentStatus)
              || "rejected".equals(agentStatus)
              || "claimed".equals(agentStatus)) {
            continue;
          }
          agentData.put("status", "revoked");
          agentData.put("updated_at", nowTs);
          storage.putAgent(agentId, agentData);
        }
        hostData.put("status", "revoked");
        hostData.put("updated_at", nowTs);
        storage.putHost(hostId, hostData);
      }
    }

    realm.removeClient(client.getId());
    emitAdminEvent("agent-auth/organization/" + orgId + "/agent-environment/" + clientId,
        OperationType.DELETE, Map.of("client_id", clientId, "organization_id", orgId));
    return Response.noContent().build();
  }

  private static String generateClientSecret() {
    byte[] bytes = new byte[32];
    new java.security.SecureRandom().nextBytes(bytes);
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  // --- Phase 5: org-admin self-service capability endpoints ---

  /**
   * Phase 5: register a capability scoped to an organization. {@code organization_id} is taken from
   * the path — body cannot override. Authorized for realm-admins or
   * {@code manage-organization}-role holders who are members of the org.
   */
  @POST
  @Path("organizations/{orgId}/capabilities")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response registerOrgCapability(@PathParam("orgId") String orgId,
      Map<String, Object> requestBody) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }
    String name = (String) requestBody.get("name");
    if (name == null || name.isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing name")).build();
    }
    if (!CAPABILITY_NAME_PATTERN.matcher(name).matches()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "Capability name must match [a-zA-Z0-9_]+"))
          .build();
    }
    String visibility = (String) requestBody.getOrDefault("visibility", "authenticated");
    if (!"authenticated".equals(visibility) && !"public".equals(visibility)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Invalid visibility")).build();
    }
    Response capabilityFieldValidation = validateCapabilityFields(requestBody);
    if (capabilityFieldValidation != null) {
      return capabilityFieldValidation;
    }
    Response gateValidation = validateGateFields(requestBody);
    if (gateValidation != null) {
      return gateValidation;
    }

    // Force org_id from path. Body cannot override the tenant scope.
    Map<String, Object> capabilityToStore = new HashMap<>(requestBody);
    capabilityToStore.put("organization_id", orgId);

    if (storage().putCapabilityIfAbsent(name, capabilityToStore) != null) {
      return Response.status(409)
          .entity(Map.of("error", "capability_exists", "message", "Capability already exists"))
          .build();
    }
    emitAdminEvent("agent-auth/organization/" + orgId + "/capability/" + name,
        OperationType.CREATE, capabilityToStore);
    return Response.status(201).entity(capabilityToStore).build();
  }

  /**
   * Phase 5: list capabilities scoped to one organization. Authorized for realm-admins or
   * org-admins. Returns only caps whose {@code organization_id} matches the path; never leaks
   * NULL-org or other-org caps.
   */
  @GET
  @Path("organizations/{orgId}/capabilities")
  @Produces(MediaType.APPLICATION_JSON)
  public Response listOrgCapabilities(@PathParam("orgId") String orgId) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);
    List<Map<String, Object>> filtered = new ArrayList<>();
    for (Map<String, Object> cap : storage().listCapabilities()) {
      if (orgId.equals(cap.get("organization_id"))) {
        filtered.add(cap);
      }
    }
    return Response.ok(Map.of("capabilities", filtered)).build();
  }

  /**
   * Phase 5: update an org-scoped capability. The caller must be authorized for the path's org AND
   * the target capability must already belong to that org — caps with a different
   * {@code organization_id} are not editable through this endpoint (org-admins can't sneak in
   * cross-tenant edits).
   */
  @PUT
  @Path("organizations/{orgId}/capabilities/{name}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response updateOrgCapability(@PathParam("orgId") String orgId,
      @PathParam("name") String name, Map<String, Object> requestBody) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }
    AgentAuthStorage storage = storage();
    Map<String, Object> existing = storage.getCapability(name);
    if (existing == null || !orgId.equals(existing.get("organization_id"))) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found",
              "message", "Capability not found in this organization"))
          .build();
    }
    Response capabilityFieldValidation = validateCapabilityFields(requestBody);
    if (capabilityFieldValidation != null) {
      return capabilityFieldValidation;
    }
    Response gateValidation = validateGateFields(requestBody);
    if (gateValidation != null) {
      return gateValidation;
    }
    Map<String, Object> updated = new HashMap<>(requestBody);
    updated.put("name", name);
    updated.put("organization_id", orgId);
    storage.putCapability(name, updated);
    emitAdminEvent("agent-auth/organization/" + orgId + "/capability/" + name,
        OperationType.UPDATE, updated);
    return Response.ok(updated).build();
  }

  /**
   * Phase 5: delete an org-scoped capability. Same ownership check as update — only org members (or
   * realm-admin) can delete, and only if the cap belongs to the path's org.
   */
  @DELETE
  @Path("organizations/{orgId}/capabilities/{name}")
  public Response deleteOrgCapability(@PathParam("orgId") String orgId,
      @PathParam("name") String name) {
    Response orgsErr = orgsEnabledOrError();
    if (orgsErr != null) {
      return orgsErr;
    }
    requireOrgAdmin(orgId);
    AgentAuthStorage storage = storage();
    Map<String, Object> existing = storage.getCapability(name);
    if (existing == null || !orgId.equals(existing.get("organization_id"))) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found",
              "message", "Capability not found in this organization"))
          .build();
    }
    storage.removeCapability(name);
    emitAdminEvent("agent-auth/organization/" + orgId + "/capability/" + name,
        OperationType.DELETE, existing);
    return Response.noContent().build();
  }

  /**
   * Phase 5 of the multi-tenant authz plan: gate the {@code /organizations/{orgId}/capabilities}
   * endpoints. Returns the resolved {@link OrganizationModel} on success; throws
   * {@code WebApplicationException} on failure (404 if the org doesn't exist, 403 otherwise).
   * Allowed callers are realm-admins (legacy super-user privilege) OR realm-management
   * {@code manage-organization}-role holders who are also members of the target org. The
   * org-membership check prevents an admin with realm-wide {@code manage-organization} from writing
   * to an org they don't belong to.
   */
  private org.keycloak.models.OrganizationModel requireOrgAdmin(String orgId) {
    if (auth == null || auth.adminAuth() == null || auth.adminAuth().getUser() == null) {
      throw new jakarta.ws.rs.ForbiddenException("Admin authentication required");
    }
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      throw new jakarta.ws.rs.InternalServerErrorException("Realm not in context");
    }
    // Callers must run orgsEnabledOrError() first; we still defend-in-depth here, but the explicit
    // guard at the endpoint is what produces a 501 response — RestEasy's WebApplicationException
    // mapping inside KC's pipeline collapses thrown 501s to a generic 500.
    org.keycloak.organization.OrganizationProvider orgProvider;
    try {
      orgProvider = session.getProvider(org.keycloak.organization.OrganizationProvider.class);
    } catch (RuntimeException e) {
      throw new jakarta.ws.rs.InternalServerErrorException(
          "Organizations feature unavailable on this realm");
    }
    if (orgProvider == null || !realm.isOrganizationsEnabled()) {
      throw new jakarta.ws.rs.InternalServerErrorException(
          "Organizations feature not enabled on this realm");
    }
    org.keycloak.models.OrganizationModel org = orgProvider.getById(orgId);
    if (org == null) {
      throw new jakarta.ws.rs.NotFoundException("Organization not found");
    }
    org.keycloak.models.UserModel user = auth.adminAuth().getUser();
    // Realm-admin override: if the caller has manage-realm, skip the per-org membership/role
    // checks. Manage-realm is super-user-equivalent; gating it on org membership would be
    // strictly weaker than today's /capabilities endpoints.
    boolean isRealmAdmin = false;
    try {
      auth.realm().requireManageRealm();
      isRealmAdmin = true;
    } catch (RuntimeException denied) {
      isRealmAdmin = false; // NOPMD: not a realm-admin; fall through to org-admin checks below
    }
    if (!isRealmAdmin) {
      org.keycloak.models.ClientModel realmManagement = realm.getClientByClientId(
          "realm-management");
      org.keycloak.models.RoleModel manageOrg = realmManagement == null
          ? null
          : realmManagement.getRole("manage-organization");
      if (manageOrg == null || !user.hasRole(manageOrg)) {
        throw new jakarta.ws.rs.ForbiddenException(
            "Caller lacks manage-organization role");
      }
      if (!orgProvider.isMember(org, user)) {
        throw new jakarta.ws.rs.ForbiddenException(
            "Caller is not a member of the target organization");
      }
    }
    return org;
  }

  /**
   * Returns a 501 Not Implemented response when KC's Organizations feature is unavailable on this
   * realm, or {@code null} when orgs are usable. Org-scoped endpoints call this before
   * {@link #requireOrgAdmin} so clients see 501 (with a structured {@code
   * organizations_feature_disabled} error) instead of a generic 500. Returning a response rather
   * than throwing avoids RestEasy/KC mapping the wrapped status to 500 inside this pipeline.
   *
   * <p>
   * Distinct from 404 (org not found) so clients can tell "feature off" from "wrong orgId" via
   * status alone.
   */
  private Response orgsEnabledOrError() {
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      return null; // requireOrgAdmin will surface the realm-missing case as 500
    }
    org.keycloak.organization.OrganizationProvider orgProvider;
    try {
      orgProvider = session.getProvider(org.keycloak.organization.OrganizationProvider.class);
    } catch (RuntimeException e) {
      orgProvider = null;
    }
    if (orgProvider == null || !realm.isOrganizationsEnabled()) {
      return Response.status(501)
          .entity(Map.of("error", "organizations_feature_disabled",
              "message", "Organizations feature not enabled on this realm"))
          .build();
    }
    return null;
  }

  /**
   * AAP §2.12 capability-object shape validation, applied before the cap is persisted by either of
   * the realm- or org-scoped admin endpoints. The protocol requires:
   *
   * <ul>
   * <li>{@code description} — required, non-blank string.</li>
   * <li>{@code location} — required, non-blank string. Per AAP §2.12 a locationless capability MUST
   * execute at {@code default_location} from discovery (§2.15 / §5.1). This implementation lacks a
   * backend that can dispatch to {@code default_location}, so admin-time registration rejects
   * locationless caps before they enter the catalog. Clients therefore never see a capability they
   * can't validly execute. Returns {@code invalid_capability_location}.</li>
   * <li>{@code input} — optional; if present, MUST be a JSON object (a {@code Map}). Scalars,
   * arrays, and strings are rejected.</li>
   * <li>{@code output} — same rule as {@code input}.</li>
   * </ul>
   *
   * <p>
   * {@code name} and {@code visibility} are checked at the call site because their messages and
   * default-handling differ; this helper covers the shared shape rules. Returning a
   * {@link Response} lets each endpoint short-circuit cleanly without throwing.
   */
  private static Response validateCapabilityFields(Map<String, Object> requestBody) {
    Object rawDescription = requestBody.get("description");
    if (!(rawDescription instanceof String) || ((String) rawDescription).trim().isEmpty()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "description is required and must be a non-blank string"))
          .build();
    }
    Object rawLocation = requestBody.get("location");
    if (!(rawLocation instanceof String) || ((String) rawLocation).trim().isEmpty()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_capability_location",
              "message", "location is required and must be a non-blank string"))
          .build();
    }
    // AAP-ADMIN-004: location must be a syntactically valid absolute URL whose scheme is https
    // (or http for localhost / when the test-only insecure override is set). The original check
    // only enforced non-blankness, so a cap with `location: "not a url"` would land in the
    // catalog and fail later at execute-time. Parsing here moves the failure to admin time and
    // makes the error symmetric with the rest of the catalog shape rules.
    Response locationUrlValidation = validateCapabilityLocationUrl(
        ((String) rawLocation).trim());
    if (locationUrlValidation != null) {
      return locationUrlValidation;
    }
    if (requestBody.containsKey("input") && !(requestBody.get("input") instanceof Map)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "input must be a JSON object when present"))
          .build();
    }
    if (requestBody.containsKey("output") && !(requestBody.get("output") instanceof Map)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "output must be a JSON object when present"))
          .build();
    }
    return null;
  }

  /**
   * AAP-ADMIN-004: parse the cap's {@code location} as an absolute URL and reject anything that
   * isn't well-formed. {@code https} is required in production; {@code http} is permitted only for
   * {@code localhost} / {@code 127.0.0.1} / {@code ::1} or when the test-only system property
   * {@code agent-auth.allow-insecure-capability-location} is {@code true}. Returns a 400
   * {@code invalid_capability_location} response on failure, or null when the URL is acceptable.
   */
  private static Response validateCapabilityLocationUrl(String location) {
    URI uri;
    try {
      uri = new URI(location);
    } catch (URISyntaxException e) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_capability_location",
              "message", "location must be a syntactically valid URL"))
          .build();
    }
    if (!uri.isAbsolute() || uri.getScheme() == null || uri.getHost() == null
        || uri.getHost().isBlank()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_capability_location",
              "message", "location must be an absolute URL with a scheme and host"))
          .build();
    }
    String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
    if ("https".equals(scheme)) {
      return null;
    }
    if ("http".equals(scheme)) {
      String host = uri.getHost().toLowerCase(java.util.Locale.ROOT);
      boolean isLocalhost = "localhost".equals(host) || "127.0.0.1".equals(host)
          || "[::1]".equals(host) || "::1".equals(host);
      if (isLocalhost) {
        return null;
      }
      if ("true".equals(System.getProperty("agent-auth.allow-insecure-capability-location"))) {
        return null;
      }
    }
    return Response.status(400)
        .entity(Map.of("error", "invalid_capability_location",
            "message", "location must use https (http allowed only for localhost or when"
                + " agent-auth.allow-insecure-capability-location=true)"))
        .build();
  }

  /**
   * Phase 1 of the multi-tenant authz plan: validate the optional {@code organization_id} and
   * {@code required_role} gate fields. Both are nullable. When present, they must be non-blank
   * strings; existence-against-KC validation (org id resolves to a real KC org, role name resolves
   * to a real realm role) is deferred until the use case asks for it.
   */
  private static Response validateGateFields(Map<String, Object> requestBody) {
    Object rawOrgId = requestBody.get("organization_id");
    if (rawOrgId != null
        && (!(rawOrgId instanceof String) || ((String) rawOrgId).isBlank())) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "organization_id must be a non-blank string"))
          .build();
    }
    Object rawRequiredRole = requestBody.get("required_role");
    if (rawRequiredRole != null
        && (!(rawRequiredRole instanceof String) || ((String) rawRequiredRole).isBlank())) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "required_role must be a non-blank string"))
          .build();
    }
    return null;
  }

  /**
   * AAP-ADMIN-003: discriminated result of admin host-key parsing. Either {@link #thumbprint} is
   * non-null (key is a valid Ed25519 OKP and the JWK thumbprint is the host id), or
   * {@link #errorResponse} is non-null (the caller should return that 400 response immediately).
   */
  private record HostKeyParseResult(String thumbprint, Response errorResponse) {
  }

  /**
   * AAP-ADMIN-003: parse the admin-supplied {@code host_public_key} JWK as an Ed25519 OKP and
   * compute its thumbprint. Without the curve check, any OctetKeyPair-shaped key (e.g. X25519)
   * survives admin-time validation, lands in storage as an active host record, and only fails at
   * first JWT verification when {@link HostJwtVerifier} requires {@code Ed25519}. That leaves an
   * unverifiable host wedged in the catalog. Failing here keeps the catalog consistent with the
   * runtime crypto contract.
   */
  private static HostKeyParseResult parseEd25519HostKeyThumbprint(
      Map<String, Object> hostPublicKeyMap) {
    OctetKeyPair okp;
    try {
      okp = OctetKeyPair.parse(hostPublicKeyMap);
    } catch (Exception e) {
      return new HostKeyParseResult(null,
          Response.status(400)
              .entity(Map.of("error", "invalid_request",
                  "message", "Invalid host_public_key"))
              .build());
    }
    if (!Curve.Ed25519.equals(okp.getCurve())) {
      return new HostKeyParseResult(null,
          Response.status(400)
              .entity(Map.of("error", "unsupported_algorithm",
                  "message", "host_public_key must be an Ed25519 OKP JWK"))
              .build());
    }
    try {
      return new HostKeyParseResult(okp.computeThumbprint().toString(), null);
    } catch (Exception e) {
      return new HostKeyParseResult(null,
          Response.status(400)
              .entity(Map.of("error", "invalid_request",
                  "message", "Invalid host_public_key"))
              .build());
    }
  }

  /**
   * Identity to record in {@code granted_by} for admin-mediated approvals. Per AAP §3.3.1,
   * {@code granted_by} records the admin or reviewer who approved a grant, which is distinct from
   * {@code user_id} (the end-user on whose behalf the agent acts).
   */
  private String approverUserId() {
    if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
      return auth.adminAuth().getUser().getId();
    }
    return "admin";
  }

  private void emitAdminEvent(String resourcePath, OperationType operation,
      Map<String, Object> representation) {
    if (adminEvent != null) {
      adminEvent.resource(ResourceType.CUSTOM)
          .resourcePath(resourcePath)
          .operation(operation)
          .representation(representation)
          .success();
    }
  }

  @Override
  public void close() {
  }
}
