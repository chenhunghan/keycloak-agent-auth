package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Index;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * Phase 3 of the multi-tenant authz plan: a normalized join table mirroring the per-grant subset of
 * {@code agent.agent_capability_grants}. The blob nested in {@code AGENT_AUTH_AGENT.PAYLOAD}
 * remains the source of truth for application reads in this phase — this table is a sync-on-write
 * secondary index that {@code JpaStorage.putAgent} maintains by deleting and re-inserting all rows
 * for an agent on every save. Phase 4's eager cascade and future Phase 6 read-path swaps can query
 * this table by {@code (capability_name, status)} or {@code (agent_id, status)}.
 */
@Entity
@Table(name = "AGENT_AUTH_AGENT_GRANT", indexes = {
    @Index(name = "IDX_AGENT_AUTH_AGENT_GRANT_CAP", columnList = "CAPABILITY_NAME,STATUS"),
    @Index(name = "IDX_AGENT_AUTH_AGENT_GRANT_AGENT", columnList = "AGENT_ID,STATUS")
})
@IdClass(AgentGrantEntity.AgentGrantId.class)
@NamedQueries({
    @NamedQuery(name = "AgentGrantEntity.findByAgent", query = "select g from AgentGrantEntity g where g.agentId = :agentId"),
    @NamedQuery(name = "AgentGrantEntity.deleteByAgent", query = "delete from AgentGrantEntity g where g.agentId = :agentId"),
    @NamedQuery(name = "AgentGrantEntity.findByCapabilityAndStatus", query = "select g from AgentGrantEntity g where g.capabilityName = :capabilityName "
        + "and g.status = :status")
})
public class AgentGrantEntity {

  @Id
  @Column(name = "AGENT_ID", length = 36)
  private String agentId;

  @Id
  @Column(name = "CAPABILITY_NAME", length = 255)
  private String capabilityName;

  @Column(name = "STATUS", length = 32, nullable = false)
  private String status;

  @Column(name = "GRANTED_BY", length = 64)
  private String grantedBy;

  @Column(name = "REASON", length = 64)
  private String reason;

  @Column(name = "CONSTRAINTS_JSON", columnDefinition = "TEXT")
  private String constraintsJson;

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

  public String getAgentId() {
    return agentId;
  }

  public void setAgentId(String agentId) {
    this.agentId = agentId;
  }

  public String getCapabilityName() {
    return capabilityName;
  }

  public void setCapabilityName(String capabilityName) {
    this.capabilityName = capabilityName;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getGrantedBy() {
    return grantedBy;
  }

  public void setGrantedBy(String grantedBy) {
    this.grantedBy = grantedBy;
  }

  public String getReason() {
    return reason;
  }

  public void setReason(String reason) {
    this.reason = reason;
  }

  public String getConstraintsJson() {
    return constraintsJson;
  }

  public void setConstraintsJson(String constraintsJson) {
    this.constraintsJson = constraintsJson;
  }

  public long getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(long createdAt) {
    this.createdAt = createdAt;
  }

  public long getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(long updatedAt) {
    this.updatedAt = updatedAt;
  }

  /**
   * Composite primary key for {@link AgentGrantEntity}: {@code (agentId, capabilityName)}. Required
   * by JPA's {@code @IdClass} contract; equals/hashCode keyed on both fields.
   */
  public static class AgentGrantId implements Serializable {
    private static final long serialVersionUID = 1L;

    private String agentId;
    private String capabilityName;

    public AgentGrantId() {
    }

    public AgentGrantId(String agentId, String capabilityName) {
      this.agentId = agentId;
      this.capabilityName = capabilityName;
    }

    public String getAgentId() {
      return agentId;
    }

    public void setAgentId(String agentId) {
      this.agentId = agentId;
    }

    public String getCapabilityName() {
      return capabilityName;
    }

    public void setCapabilityName(String capabilityName) {
      this.capabilityName = capabilityName;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof AgentGrantId other)) {
        return false;
      }
      return Objects.equals(agentId, other.agentId)
          && Objects.equals(capabilityName, other.capabilityName);
    }

    @Override
    public int hashCode() {
      return Objects.hash(agentId, capabilityName);
    }
  }
}
