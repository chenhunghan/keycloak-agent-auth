package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
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
import java.time.Instant;
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
    agentData.put("updated_at", Instant.now().toString());
    storage.putAgent(id, agentData);
    emitAdminEvent("agent-auth/agent/" + id + "/capability/" + capability + "/approve",
        OperationType.ACTION, targetGrant);
    return Response.ok(targetGrant).build();
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

    String hostId;
    try {
      hostId = OctetKeyPair.parse(hostPublicKeyMap).computeThumbprint().toString();
    } catch (Exception e) {
      return Response.status(400).entity(Map.of("error", "invalid_request", "message",
          "Invalid host_public_key")).build();
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

    Object name = requestBody.get("name");
    if (name instanceof String && !((String) name).isBlank()) {
      hostData.put("name", name);
    }
    Object description = requestBody.get("description");
    if (description instanceof String && !((String) description).isBlank()) {
      hostData.put("description", description);
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
  public Response getAgent(@PathParam("id") String id) {
    requireManageRealm();
    Map<String, Object> agentData = storage().getAgent(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "agent_not_found",
          "message", "Agent not found")).build();
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
    return Response.ok(Map.of("grants", storage().findGrantsByAgent(id))).build();
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
    int removed = storage().deletePendingAgentsOlderThan(thresholdMs);
    return Response.ok(Map.of("removed", removed, "threshold_seconds", thresholdSec)).build();
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
