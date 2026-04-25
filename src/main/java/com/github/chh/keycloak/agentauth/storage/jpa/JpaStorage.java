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
    return entity == null ? null : deserialize(entity.getPayload());
  }

  @Override
  public void putHost(String hostId, Map<String, Object> host) {
    EntityManager em = em();
    HostEntity entity = em.find(HostEntity.class, hostId);
    long now = System.currentTimeMillis();
    String json = serialize(host);
    String status = (String) host.get("status");
    String userId = stringField(host, "user_id");
    if (entity == null) {
      entity = new HostEntity();
      entity.setId(hostId);
      entity.setCreatedAt(now);
      entity.setStatus(status);
      entity.setPayload(json);
      entity.setUserId(userId);
      entity.setUpdatedAt(now);
      em.persist(entity);
    } else {
      entity.setStatus(status);
      entity.setPayload(json);
      entity.setUserId(userId);
      entity.setUpdatedAt(now);
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

  // --- Agents ---

  @Override
  public Map<String, Object> getAgent(String agentId) {
    AgentEntity entity = em().find(AgentEntity.class, agentId);
    return entity == null ? null : deserialize(entity.getPayload());
  }

  @Override
  public void putAgent(String agentId, Map<String, Object> agent) {
    EntityManager em = em();
    AgentEntity entity = em.find(AgentEntity.class, agentId);
    long now = System.currentTimeMillis();
    String json = serialize(agent);
    String hostId = (String) agent.get("host_id");
    String thumbprint = (String) agent.get("agent_key_thumbprint");
    String status = (String) agent.get("status");
    String userId = stringField(agent, "user_id");
    String userCode = stringField(agent, "user_code");
    if (entity == null) {
      entity = new AgentEntity();
      entity.setId(agentId);
      entity.setCreatedAt(now);
      entity.setHostId(hostId);
      entity.setKeyThumbprint(thumbprint);
      entity.setStatus(status);
      entity.setPayload(json);
      entity.setUserId(userId);
      entity.setUserCode(userCode);
      entity.setUpdatedAt(now);
      em.persist(entity);
    } else {
      entity.setHostId(hostId);
      entity.setKeyThumbprint(thumbprint);
      entity.setStatus(status);
      entity.setPayload(json);
      entity.setUserId(userId);
      entity.setUserCode(userCode);
      entity.setUpdatedAt(now);
    }
    syncAgentGrants(em, agentId, agent, now);
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
    return results.isEmpty() ? null : deserialize(results.get(0).getPayload());
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
  public Map<String, Object> findAgentByKeyAndHost(String agentKeyThumbprint, String hostId) {
    List<AgentEntity> results = em()
        .createNamedQuery("AgentEntity.findByKeyAndHost", AgentEntity.class)
        .setParameter("hostId", hostId)
        .setParameter("keyThumbprint", agentKeyThumbprint)
        .setMaxResults(1)
        .getResultList();
    return results.isEmpty() ? null : deserialize(results.get(0).getPayload());
  }

  @Override
  public List<Map<String, Object>> findAgentsByHost(String hostId) {
    List<AgentEntity> results = em()
        .createNamedQuery("AgentEntity.findByHost", AgentEntity.class)
        .setParameter("hostId", hostId)
        .getResultList();
    List<Map<String, Object>> out = new ArrayList<>(results.size());
    for (AgentEntity e : results) {
      out.add(deserialize(e.getPayload()));
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
      out.add(deserialize(row.getPayload()));
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
      out.add(deserialize(e.getPayload()));
    }
    return out;
  }

  // --- Capabilities ---

  @Override
  public Map<String, Object> getCapability(String name) {
    CapabilityEntity entity = em().find(CapabilityEntity.class, name);
    return entity == null ? null : deserialize(entity.getPayload());
  }

  @Override
  public Map<String, Object> putCapabilityIfAbsent(String name, Map<String, Object> capability) {
    EntityManager em = em();
    CapabilityEntity existing = em.find(CapabilityEntity.class, name);
    if (existing != null) {
      return deserialize(existing.getPayload());
    }
    long now = System.currentTimeMillis();
    CapabilityEntity entity = new CapabilityEntity();
    entity.setName(name);
    entity.setPayload(serialize(capability));
    entity.setCreatedAt(now);
    entity.setUpdatedAt(now);
    em.persist(entity);
    return null;
  }

  @Override
  public void putCapability(String name, Map<String, Object> capability) {
    EntityManager em = em();
    CapabilityEntity entity = em.find(CapabilityEntity.class, name);
    long now = System.currentTimeMillis();
    String json = serialize(capability);
    if (entity == null) {
      entity = new CapabilityEntity();
      entity.setName(name);
      entity.setCreatedAt(now);
      entity.setPayload(json);
      entity.setUpdatedAt(now);
      em.persist(entity);
    } else {
      entity.setPayload(json);
      entity.setUpdatedAt(now);
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
      out.add(deserialize(e.getPayload()));
    }
    return out;
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

  @SuppressWarnings("unchecked")
  private static Map<String, Object> deserialize(String json) {
    try {
      return JsonSerialization.readValue(json, Map.class);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to deserialize agent-auth payload", e);
    }
  }
}
