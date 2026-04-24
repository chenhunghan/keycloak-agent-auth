package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
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
    targetGrant.put("granted_by", "admin");
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

  private void requireManageRealm() {
    if (auth != null) {
      auth.realm().requireManageRealm();
    }
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
