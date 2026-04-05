package com.github.chh.keycloak.agentauth;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;

public class AgentAuthAdminResourceProvider implements AdminRealmResourceProvider {

  private static final Pattern CAPABILITY_NAME_PATTERN = Pattern.compile("[a-z0-9_]+");
  private final KeycloakSession session;

  public AgentAuthAdminResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource(KeycloakSession session, org.keycloak.models.RealmModel realm,
      org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator auth,
      org.keycloak.services.resources.admin.AdminEventBuilder adminEvent) {
    return this;
  }

  @POST
  @Path("capabilities")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response registerCapability(Map<String, Object> requestBody) {
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    String name = (String) requestBody.get("name");
    String location = (String) requestBody.get("location");
    if (location == null || location.isBlank()) {
      String realmName = session.getContext().getRealm().getName();
      String issuer = session.getContext().getUri(org.keycloak.urls.UrlType.FRONTEND)
          .getBaseUriBuilder().path("realms").path(realmName).path("agent-auth").build()
          .toString();
      location = issuer + "/capability/execute";
      requestBody = new HashMap<>(requestBody);
      requestBody.put("location", location);
    }

    if (name == null || location == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Missing name or location"))
          .build();
    }

    if (!CAPABILITY_NAME_PATTERN.matcher(name).matches()) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request",
              "message", "Capability name must match [a-z0-9_]+"))
          .build();
    }

    String visibility = (String) requestBody.getOrDefault("visibility", "authenticated");
    if (!"authenticated".equals(visibility) && !"public".equals(visibility)) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Invalid visibility")).build();
    }

    if (InMemoryRegistry.CAPABILITIES.putIfAbsent(name, requestBody) != null) {
      return Response.status(409)
          .entity(Map.of("error", "capability_exists", "message", "Capability already exists"))
          .build();
    }

    return Response.status(201).entity(requestBody).build();
  }

  @PUT
  @Path("capabilities/{name}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response updateCapability(@PathParam("name") String name,
      Map<String, Object> requestBody) {
    if (requestBody == null) {
      return Response.status(400)
          .entity(Map.of("error", "invalid_request", "message", "Empty body")).build();
    }

    Map<String, Object> existingCapability = InMemoryRegistry.CAPABILITIES.get(name);
    if (existingCapability == null) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }

    Map<String, Object> updatedCapability = new HashMap<>(requestBody);
    updatedCapability.put("name", name);
    InMemoryRegistry.CAPABILITIES.put(name, updatedCapability);

    return Response.ok(updatedCapability).build();
  }

  @DELETE
  @Path("capabilities/{name}")
  public Response deleteCapability(@PathParam("name") String name) {
    Map<String, Object> removedCapability = InMemoryRegistry.CAPABILITIES.remove(name);
    if (removedCapability == null) {
      return Response.status(404)
          .entity(Map.of("error", "capability_not_found", "message", "Capability not found"))
          .build();
    }

    return Response.noContent().build();
  }

  @POST
  @Path("agents/{id}/expire")
  @Produces(MediaType.APPLICATION_JSON)
  @SuppressWarnings("unchecked")
  public Response expireAgent(@jakarta.ws.rs.PathParam("id") String id,
      Map<String, Object> requestBody) {
    Map<String, Object> agentData = InMemoryRegistry.AGENTS.get(id);
    if (agentData == null) {
      return Response.status(404).entity(Map.of("error", "not_found")).build();
    }
    agentData.put("status", "expired");
    if (requestBody != null && Boolean.TRUE.equals(requestBody.get("absolute_lifetime_elapsed"))) {
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
    return Response.ok(agentData).build();
  }

  @Override
  public void close() {
  }
}
