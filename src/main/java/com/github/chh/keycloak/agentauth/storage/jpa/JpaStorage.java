package com.github.chh.keycloak.agentauth.storage.jpa;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * JPA-backed {@link AgentAuthStorage} implementation. Payloads are stored as TEXT/JSON with a few
 * queryable columns on the side (see {@link HostEntity}, {@link AgentEntity}, etc.).
 *
 * <p>
 * The {@link EntityManager} is enlisted in the current {@link KeycloakSession}'s transaction — this
 * class never begins, commits or closes a transaction. Maps returned from the storage methods are
 * fresh deserialized copies; callers that mutate must follow up with an explicit {@code putAgent}
 * or {@code putHost} call.
 */
public class JpaStorage implements AgentAuthStorage {

  private final KeycloakSession session;

  public JpaStorage(KeycloakSession session) {
    this.session = session;
  }

  private EntityManager em() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

  // --- Hosts ---

  @Override
  public Map<String, Object> getHost(String hostId) {
    HostEntity entity = em().find(HostEntity.class, hostId);
    return entity == null ? null : hostToMap(entity);
  }

  @Override
  public void putHost(String hostId, Map<String, Object> host) {
    EntityManager em = em();
    HostEntity entity = em.find(HostEntity.class, hostId);
    long now = System.currentTimeMillis();
    if (entity == null) {
      entity = new HostEntity();
      entity.setId(hostId);
      entity.setCreatedAt(now);
      entity.setUpdatedAt(now);
      applyHostFields(entity, host);
      em.persist(entity);
    } else {
      entity.setUpdatedAt(now);
      applyHostFields(entity, host);
    }
  }

  @Override
  public void removeHost(String hostId) {
    EntityManager em = em();
    HostEntity entity = em.find(HostEntity.class, hostId);
    if (entity != null) {
      em.remove(entity);
    }
  }

  @Override
  public Map<String, Object> findHostByJwksUrl(String hostJwksUrl) {
    if (hostJwksUrl == null || hostJwksUrl.isBlank()) {
      return null;
    }
    List<HostEntity> rows = em()
        .createNamedQuery("HostEntity.findByJwksUrl", HostEntity.class)
        .setParameter("hostJwksUrl", hostJwksUrl)
        .setMaxResults(1)
        .getResultList();
    return rows.isEmpty() ? null : hostToMap(rows.get(0));
  }

  // --- Agents ---

  @Override
  public Map<String, Object> getAgent(String agentId) {
    AgentEntity entity = em().find(AgentEntity.class, agentId);
    return entity == null ? null : agentToMap(entity);
  }

  @Override
  public void putAgent(String agentId, Map<String, Object> agent) {
    EntityManager em = em();
    AgentEntity entity = em.find(AgentEntity.class, agentId);
    long now = System.currentTimeMillis();
    String priorGrantsJson;
    if (entity == null) {
      entity = new AgentEntity();
      entity.setId(agentId);
      entity.setCreatedAt(now);
      entity.setUpdatedAt(now);
      priorGrantsJson = null;
      applyAgentFields(entity, agent);
      em.persist(entity);
    } else {
      priorGrantsJson = entity.getAgentGrants();
      entity.setUpdatedAt(now);
      applyAgentFields(entity, agent);
    }
    // Only re-sync the AGENT_AUTH_AGENT_GRANT secondary index when the grants array actually
    // changed. Skipping the unchanged case avoids a delete-and-replace round-trip on every
    // putAgent (e.g. when /capability/execute updates last_used_at) and keeps long-running
    // transactions like the streaming proxy from holding row locks against concurrent revokes.
    String newGrantsJson = entity.getAgentGrants();
    if (!java.util.Objects.equals(priorGrantsJson, newGrantsJson)) {
      syncAgentGrants(em, agentId, agent, now);
    }
  }

  @Override
  public Map<String, Object> findAgentByUserCode(String userCode) {
    if (userCode == null) {
      return null;
    }
    List<AgentEntity> results = em()
        .createNamedQuery("AgentEntity.findByUserCode", AgentEntity.class)
        .setParameter("userCode", userCode)
        .setMaxResults(1)
        .getResultList();
    return results.isEmpty() ? null : agentToMap(results.get(0));
  }

  @Override
  public int deletePendingAgentsOlderThan(long thresholdEpochMs) {
    EntityManager em = em();
    // Phase 3: cascade the bulk delete to the grants table. JPQL bulk-delete bypasses JPA
    // cascade, so the grants are removed explicitly first.
    em.createQuery("delete from AgentGrantEntity g where g.agentId in ("
        + "select a.id from AgentEntity a where a.status = 'pending' and a.createdAt < :threshold"
        + ")")
        .setParameter("threshold", thresholdEpochMs)
        .executeUpdate();
    return em
        .createQuery("delete from AgentEntity a where a.status = 'pending'"
            + " and a.createdAt < :threshold")
        .setParameter("threshold", thresholdEpochMs)
        .executeUpdate();
  }

  @Override
  public int deleteOrphanedPendingHostsOlderThan(long thresholdEpochMs) {
    // The NOT EXISTS subquery sees the agent table after the agent sweep has committed in the
    // surrounding transaction (PendingAgentCleanup runs both deletes in the same JPA tx).
    // Hosts whose only agent was just-deleted become orphan and qualify; hosts that still have
    // a (younger) pending agent or any non-pending agent are left alone.
    return em()
        .createQuery("delete from HostEntity h where h.status = 'pending'"
            + " and h.createdAt < :threshold"
            + " and not exists (select 1 from AgentEntity a where a.hostId = h.id)")
        .setParameter("threshold", thresholdEpochMs)
        .executeUpdate();
  }

  @Override
  public Map<String, Object> findAgentByKeyAndHost(String agentKeyThumbprint, String hostId) {
    List<AgentEntity> rows = em()
        .createNamedQuery("AgentEntity.findByKeyAndHost", AgentEntity.class)
        .setParameter("hostId", hostId)
        .setParameter("keyThumbprint", agentKeyThumbprint)
        .setMaxResults(1)
        .getResultList();
    return rows.isEmpty() ? null : agentToMap(rows.get(0));
  }

  @Override
  public List<Map<String, Object>> findAgentsByHost(String hostId) {
    List<AgentEntity> rows = em()
        .createNamedQuery("AgentEntity.findByHost", AgentEntity.class)
        .setParameter("hostId", hostId)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(rows.size());
    for (AgentEntity e : rows) {
      out.add(agentToMap(e));
    }
    return out;
  }

  @Override
  public List<Map<String, Object>> findGrantsByAgent(String agentId) {
    if (agentId == null) {
      return new ArrayList<>();
    }
    List<AgentGrantEntity> rows = em()
        .createNamedQuery("AgentGrantEntity.findByAgent", AgentGrantEntity.class)
        .setParameter("agentId", agentId)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(rows.size());
    for (AgentGrantEntity row : rows) {
      Map<String, Object> grant = new java.util.HashMap<>();
      grant.put("agent_id", row.getAgentId());
      grant.put("capability", row.getCapabilityName());
      grant.put("status", row.getStatus());
      if (row.getGrantedBy() != null) {
        grant.put("granted_by", row.getGrantedBy());
      }
      if (row.getReason() != null) {
        grant.put("reason", row.getReason());
      }
      if (row.getConstraintsJson() != null) {
        grant.put("constraints", deserialize(row.getConstraintsJson()));
      }
      out.add(grant);
    }
    return out;
  }

  @Override
  public List<Map<String, Object>> findAgentsByUser(String userId) {
    if (userId == null) {
      return new ArrayList<>();
    }
    List<AgentEntity> rows = em()
        .createNamedQuery("AgentEntity.findByUserId", AgentEntity.class)
        .setParameter("userId", userId)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(rows.size());
    for (AgentEntity row : rows) {
      out.add(agentToMap(row));
    }
    return out;
  }

  @Override
  public List<Map<String, Object>> findHostsByUser(String userId) {
    if (userId == null) {
      return new ArrayList<>();
    }
    List<HostEntity> results = em()
        .createNamedQuery("HostEntity.findByUserId", HostEntity.class)
        .setParameter("userId", userId)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(results.size());
    for (HostEntity e : results) {
      out.add(hostToMap(e));
    }
    return out;
  }

  /**
   * Phase 6b: project a {@link HostEntity} back to the protocol-shaped map. Null columns are
   * omitted so unset fields don't surface as explicit nulls in JSON responses. Always populates
   * {@code host_id}, {@code status}, {@code created_at}, {@code updated_at} since those are
   * non-null columns.
   */
  private static Map<String, Object> hostToMap(HostEntity entity) {
    Map<String, Object> map = new java.util.HashMap<>();
    map.put("host_id", entity.getId());
    map.put("status", entity.getStatus());
    map.put("created_at", java.time.Instant.ofEpochMilli(entity.getCreatedAt()).toString());
    map.put("updated_at", java.time.Instant.ofEpochMilli(entity.getUpdatedAt()).toString());
    if (entity.getUserId() != null) {
      map.put("user_id", entity.getUserId());
    }
    if (entity.getPublicKeyJwk() != null) {
      map.put("public_key", deserialize(entity.getPublicKeyJwk()));
    }
    if (entity.getHostJwksUrl() != null) {
      map.put("host_jwks_url", entity.getHostJwksUrl());
    }
    if (entity.getHostKid() != null) {
      map.put("host_kid", entity.getHostKid());
    }
    if (entity.getName() != null) {
      map.put("name", entity.getName());
    }
    if (entity.getDescription() != null) {
      map.put("description", entity.getDescription());
    }
    if (entity.getServiceAccountClientId() != null) {
      map.put("service_account_client_id", entity.getServiceAccountClientId());
    }
    if (entity.getDefaultCapabilityGrants() != null) {
      map.put("default_capability_grants",
          deserializeList(entity.getDefaultCapabilityGrants()));
    }
    if (entity.getDefaultCapabilities() != null) {
      map.put("default_capabilities",
          deserializeList(entity.getDefaultCapabilities()));
    }
    if (entity.getLastUsedAt() != null) {
      map.put("last_used_at", entity.getLastUsedAt());
    }
    return map;
  }

  /**
   * Phase 6b: write protocol-shaped map fields onto a {@link HostEntity}. The map fully replaces
   * the prior host record (mirrors blob-write semantics). {@code created_at} timestamps from prior
   * records are not overwritten by the caller — those live in the BIGINT columns and are managed by
   * {@link #putHost} directly.
   */
  @SuppressWarnings("unchecked")
  private static void applyHostFields(HostEntity entity, Map<String, Object> host) {
    String status = stringField(host, "status");
    if (status != null) {
      entity.setStatus(status);
    }
    entity.setUserId(stringField(host, "user_id"));
    Object publicKey = host.get("public_key");
    entity.setPublicKeyJwk(
        publicKey instanceof Map<?, ?> ? serialize((Map<String, Object>) publicKey) : null);
    entity.setHostJwksUrl(stringField(host, "host_jwks_url"));
    entity.setHostKid(stringField(host, "host_kid"));
    entity.setName(stringField(host, "name"));
    entity.setDescription(stringField(host, "description"));
    entity.setServiceAccountClientId(stringField(host, "service_account_client_id"));
    Object defaults = host.get("default_capability_grants");
    entity.setDefaultCapabilityGrants(
        defaults instanceof List<?> ? serializeAny(defaults) : null);
    Object defaultCaps = host.get("default_capabilities");
    entity.setDefaultCapabilities(
        defaultCaps instanceof List<?> ? serializeAny(defaultCaps) : null);
    entity.setLastUsedAt(stringField(host, "last_used_at"));
  }

  /**
   * Phase 6c: project an {@link AgentEntity} back to the protocol-shaped map. Null columns are
   * omitted so unset fields don't surface as explicit nulls in JSON responses. Always populates the
   * non-null PK / typed columns.
   */
  private static Map<String, Object> agentToMap(AgentEntity entity) {
    Map<String, Object> map = new java.util.HashMap<>();
    map.put("agent_id", entity.getId());
    map.put("host_id", entity.getHostId());
    map.put("agent_key_thumbprint", entity.getKeyThumbprint());
    map.put("status", entity.getStatus());
    map.put("created_at", java.time.Instant.ofEpochMilli(entity.getCreatedAt()).toString());
    map.put("updated_at", java.time.Instant.ofEpochMilli(entity.getUpdatedAt()).toString());
    if (entity.getUserId() != null) {
      map.put("user_id", entity.getUserId());
    }
    if (entity.getUserCode() != null) {
      map.put("user_code", entity.getUserCode());
    }
    if (entity.getMode() != null) {
      map.put("mode", entity.getMode());
    }
    if (entity.getName() != null) {
      map.put("name", entity.getName());
    }
    if (entity.getAgentPublicKey() != null) {
      map.put("agent_public_key", deserialize(entity.getAgentPublicKey()));
    }
    if (entity.getAgentJwksUrl() != null) {
      map.put("agent_jwks_url", entity.getAgentJwksUrl());
    }
    if (entity.getAgentKid() != null) {
      map.put("agent_kid", entity.getAgentKid());
    }
    if (entity.getActivatedAt() != null) {
      map.put("activated_at", entity.getActivatedAt());
    }
    if (entity.getExpiresAt() != null) {
      map.put("expires_at", entity.getExpiresAt());
    }
    if (entity.getLastUsedAt() != null) {
      map.put("last_used_at", entity.getLastUsedAt());
    }
    if (entity.getSessionTtlResetAt() != null) {
      map.put("session_ttl_reset_at", entity.getSessionTtlResetAt());
    }
    if (entity.getMaxLifetimeResetAt() != null) {
      map.put("max_lifetime_reset_at", entity.getMaxLifetimeResetAt());
    }
    if (entity.getMaxLifetimeSeconds() != null) {
      map.put("max_lifetime_seconds", entity.getMaxLifetimeSeconds());
    }
    if (entity.getAbsoluteLifetimeSeconds() != null) {
      map.put("absolute_lifetime_seconds", entity.getAbsoluteLifetimeSeconds());
    }
    if (entity.getAbsoluteLifetimeElapsed() != null) {
      map.put("absolute_lifetime_elapsed", entity.getAbsoluteLifetimeElapsed());
    }
    if (entity.getApproval() != null) {
      map.put("approval", deserialize(entity.getApproval()));
    }
    if (entity.getReason() != null) {
      map.put("reason", entity.getReason());
    }
    if (entity.getRejectionReason() != null) {
      map.put("rejection_reason", entity.getRejectionReason());
    }
    if (entity.getRevocationReason() != null) {
      map.put("revocation_reason", entity.getRevocationReason());
    }
    if (entity.getAgentGrants() != null) {
      map.put("agent_capability_grants", deserializeList(entity.getAgentGrants()));
    }
    return map;
  }

  /**
   * Phase 6c: write protocol-shaped map fields onto an {@link AgentEntity}. The map fully replaces
   * the prior agent record (mirrors blob-write semantics). Non-null fields HOST_ID, KEY_THUMBPRINT,
   * STATUS are always set since they're {@code @Column(nullable = false)}.
   */
  @SuppressWarnings("unchecked")
  private static void applyAgentFields(AgentEntity entity, Map<String, Object> agent) {
    String hostId = stringField(agent, "host_id");
    if (hostId != null) {
      entity.setHostId(hostId);
    }
    String thumbprint = stringField(agent, "agent_key_thumbprint");
    if (thumbprint != null) {
      entity.setKeyThumbprint(thumbprint);
    }
    String status = stringField(agent, "status");
    if (status != null) {
      entity.setStatus(status);
    }
    // Test/admin backdating support: when the protocol-shaped map carries an explicit
    // `created_at_override_epoch_millis`, honour it so the absolute-lifetime clock can be
    // simulated without time travel. Normal writes never set this key — reads project the
    // entity's CREATED_AT into `created_at` (ISO string), which is intentionally not honoured
    // on writes to keep regular putAgent calls from clobbering origin timestamps.
    Long createdAtOverride = longField(agent, "created_at_override_epoch_millis");
    if (createdAtOverride != null) {
      entity.setCreatedAt(createdAtOverride);
    }
    entity.setUserId(stringField(agent, "user_id"));
    entity.setUserCode(stringField(agent, "user_code"));
    entity.setMode(stringField(agent, "mode"));
    entity.setName(stringField(agent, "name"));
    Object agentPublicKey = agent.get("agent_public_key");
    entity.setAgentPublicKey(agentPublicKey instanceof Map<?, ?>
        ? serialize((Map<String, Object>) agentPublicKey)
        : null);
    entity.setAgentJwksUrl(stringField(agent, "agent_jwks_url"));
    entity.setAgentKid(stringField(agent, "agent_kid"));
    entity.setActivatedAt(stringField(agent, "activated_at"));
    entity.setExpiresAt(stringField(agent, "expires_at"));
    entity.setLastUsedAt(stringField(agent, "last_used_at"));
    entity.setSessionTtlResetAt(longField(agent, "session_ttl_reset_at"));
    entity.setMaxLifetimeResetAt(longField(agent, "max_lifetime_reset_at"));
    entity.setMaxLifetimeSeconds(longField(agent, "max_lifetime_seconds"));
    entity.setAbsoluteLifetimeSeconds(longField(agent, "absolute_lifetime_seconds"));
    entity.setAbsoluteLifetimeElapsed(booleanField(agent, "absolute_lifetime_elapsed"));
    Object approval = agent.get("approval");
    entity.setApproval(approval instanceof Map<?, ?>
        ? serialize((Map<String, Object>) approval)
        : null);
    entity.setReason(stringField(agent, "reason"));
    entity.setRejectionReason(stringField(agent, "rejection_reason"));
    entity.setRevocationReason(stringField(agent, "revocation_reason"));
    Object grants = agent.get("agent_capability_grants");
    entity.setAgentGrants(grants instanceof List<?> ? serializeAny(grants) : null);
  }

  private static Long longField(Map<String, Object> map, String key) {
    Object value = map == null ? null : map.get(key);
    if (value instanceof Long l) {
      return l;
    }
    if (value instanceof Number n) {
      return n.longValue();
    }
    return null;
  }

  // --- Capabilities ---

  @Override
  public Map<String, Object> getCapability(String name) {
    CapabilityEntity entity = em().find(CapabilityEntity.class, name);
    return entity == null ? null : capabilityToMap(entity);
  }

  @Override
  public Map<String, Object> putCapabilityIfAbsent(String name, Map<String, Object> capability) {
    EntityManager em = em();
    CapabilityEntity existing = em.find(CapabilityEntity.class, name);
    if (existing != null) {
      return capabilityToMap(existing);
    }
    long now = System.currentTimeMillis();
    CapabilityEntity entity = new CapabilityEntity();
    entity.setName(name);
    entity.setCreatedAt(now);
    entity.setUpdatedAt(now);
    applyCapabilityFields(entity, capability);
    em.persist(entity);
    return null;
  }

  @Override
  public void putCapability(String name, Map<String, Object> capability) {
    EntityManager em = em();
    CapabilityEntity entity = em.find(CapabilityEntity.class, name);
    long now = System.currentTimeMillis();
    if (entity == null) {
      entity = new CapabilityEntity();
      entity.setName(name);
      entity.setCreatedAt(now);
      entity.setUpdatedAt(now);
      applyCapabilityFields(entity, capability);
      em.persist(entity);
    } else {
      entity.setUpdatedAt(now);
      applyCapabilityFields(entity, capability);
    }
  }

  @Override
  public void removeCapability(String name) {
    EntityManager em = em();
    CapabilityEntity entity = em.find(CapabilityEntity.class, name);
    if (entity != null) {
      em.remove(entity);
    }
  }

  @Override
  public List<Map<String, Object>> listCapabilities() {
    List<CapabilityEntity> entities = em()
        .createQuery("select c from CapabilityEntity c", CapabilityEntity.class)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(entities.size());
    for (CapabilityEntity e : entities) {
      out.add(capabilityToMap(e));
    }
    return out;
  }

  /**
   * Phase 6a: project a {@link CapabilityEntity} back to the protocol-shaped map. Null columns are
   * omitted so unset fields don't surface as explicit nulls in JSON responses.
   */
  private static Map<String, Object> capabilityToMap(CapabilityEntity entity) {
    Map<String, Object> map = new java.util.HashMap<>();
    map.put("name", entity.getName());
    if (entity.getDescription() != null) {
      map.put("description", entity.getDescription());
    }
    if (entity.getLocation() != null) {
      map.put("location", entity.getLocation());
    }
    if (entity.getVisibility() != null) {
      map.put("visibility", entity.getVisibility());
    }
    if (entity.getRequiresApproval() != null) {
      map.put("requires_approval", entity.getRequiresApproval());
    }
    if (entity.getAutoDeny() != null) {
      map.put("auto_deny", entity.getAutoDeny());
    }
    if (entity.getWriteCapable() != null) {
      map.put("write_capable", entity.getWriteCapable());
    }
    if (entity.getOrganizationId() != null) {
      map.put("organization_id", entity.getOrganizationId());
    }
    if (entity.getRequiredRole() != null) {
      map.put("required_role", entity.getRequiredRole());
    }
    if (entity.getInputSchema() != null) {
      map.put("input", deserialize(entity.getInputSchema()));
    }
    if (entity.getOutputSchema() != null) {
      map.put("output", deserialize(entity.getOutputSchema()));
    }
    return map;
  }

  /**
   * Phase 6a: write protocol-shaped map fields onto a {@link CapabilityEntity}. Missing keys leave
   * the column as-is (null on insert, or the prior value on update). This mirrors the blob-write
   * semantics where the new map fully replaces the prior payload.
   */
  @SuppressWarnings("unchecked")
  private static void applyCapabilityFields(CapabilityEntity entity, Map<String, Object> map) {
    entity.setDescription(stringField(map, "description"));
    entity.setLocation(stringField(map, "location"));
    entity.setVisibility(stringField(map, "visibility"));
    entity.setRequiresApproval(booleanField(map, "requires_approval"));
    entity.setAutoDeny(booleanField(map, "auto_deny"));
    entity.setWriteCapable(booleanField(map, "write_capable"));
    entity.setOrganizationId(stringField(map, "organization_id"));
    entity.setRequiredRole(stringField(map, "required_role"));
    Object input = map.get("input");
    entity.setInputSchema(
        input instanceof Map<?, ?> ? serialize((Map<String, Object>) input) : null);
    Object output = map.get("output");
    entity.setOutputSchema(
        output instanceof Map<?, ?> ? serialize((Map<String, Object>) output) : null);
  }

  private static Boolean booleanField(Map<String, Object> map, String key) {
    Object value = map == null ? null : map.get(key);
    return value instanceof Boolean ? (Boolean) value : null;
  }

  // --- Host-key rotation ---

  @Override
  public boolean isHostRotated(String hostId) {
    return em().find(RotatedHostEntity.class, hostId) != null;
  }

  @Override
  public void recordHostRotation(String oldHostId, String newHostId) {
    EntityManager em = em();
    RotatedHostEntity existing = em.find(RotatedHostEntity.class, oldHostId);
    if (existing != null) {
      existing.setNewHostId(newHostId);
      existing.setRotatedAt(System.currentTimeMillis());
      return;
    }
    RotatedHostEntity entity = new RotatedHostEntity();
    entity.setOldHostId(oldHostId);
    entity.setNewHostId(newHostId);
    entity.setRotatedAt(System.currentTimeMillis());
    em.persist(entity);
  }

  /**
   * Phase 3 of the multi-tenant authz plan: keep the {@code AGENT_AUTH_AGENT_GRANT} secondary index
   * in sync with the per-agent grants array nested in the JSON payload. Called from
   * {@link #putAgent} on every save. Strategy is delete-then-insert: simpler than upsert
   * reconciliation and acceptable at the per-agent scale (typically &lt; 50 grants).
   */
  @SuppressWarnings("unchecked")
  private static void syncAgentGrants(
      EntityManager em, String agentId, Map<String, Object> agent, long now) {
    em.createNamedQuery("AgentGrantEntity.deleteByAgent")
        .setParameter("agentId", agentId)
        .executeUpdate();
    Object rawGrants = agent.get("agent_capability_grants");
    if (!(rawGrants instanceof List<?>)) {
      return;
    }
    for (Object rawGrant : (List<?>) rawGrants) {
      if (!(rawGrant instanceof Map<?, ?>)) {
        continue;
      }
      Map<String, Object> grant = (Map<String, Object>) rawGrant;
      String capName = stringField(grant, "capability");
      String status = stringField(grant, "status");
      if (capName == null || status == null) {
        continue;
      }
      AgentGrantEntity row = new AgentGrantEntity();
      row.setAgentId(agentId);
      row.setCapabilityName(capName);
      row.setStatus(status);
      row.setGrantedBy(stringField(grant, "granted_by"));
      row.setReason(stringField(grant, "reason"));
      Object constraints = grant.get("constraints");
      if (constraints instanceof Map<?, ?>) {
        row.setConstraintsJson(serialize((Map<String, Object>) constraints));
      }
      row.setCreatedAt(now);
      row.setUpdatedAt(now);
      em.persist(row);
    }
  }

  // --- JSON helpers ---

  /**
   * Extracts a string field from a payload map. Returns {@code null} when the key is missing, the
   * value is {@code null}, or the value is not a {@link String}. Used to keep the queryable entity
   * columns in sync with the JSON payload for fields like {@code user_id}.
   */
  private static String stringField(Map<String, Object> map, String key) {
    Object value = map == null ? null : map.get(key);
    return value instanceof String ? (String) value : null;
  }

  private static String serialize(Map<String, Object> value) {
    try {
      return JsonSerialization.writeValueAsString(value);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to serialize agent-auth payload", e);
    }
  }

  private static String serializeAny(Object value) {
    try {
      return JsonSerialization.writeValueAsString(value);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to serialize agent-auth payload", e);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> deserialize(String json) {
    try {
      return JsonSerialization.readValue(json, Map.class);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to deserialize agent-auth payload", e);
    }
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> deserializeList(String json) {
    try {
      return JsonSerialization.readValue(json, List.class);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to deserialize agent-auth list payload", e);
    }
  }
}
