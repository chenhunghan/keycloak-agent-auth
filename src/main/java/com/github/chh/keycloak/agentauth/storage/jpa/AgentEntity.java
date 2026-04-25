package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "AGENT_AUTH_AGENT", indexes = {
    @Index(name = "IDX_AGENT_AUTH_AGENT_HOST", columnList = "HOST_ID"),
    @Index(name = "IDX_AGENT_AUTH_AGENT_HOST_KEY", columnList = "HOST_ID,KEY_THUMBPRINT"),
    @Index(name = "IDX_AGENT_AUTH_AGENT_USER", columnList = "USER_ID"),
    @Index(name = "IDX_AGENT_AUTH_AGENT_USER_CODE", columnList = "USER_CODE")
})
@NamedQueries({
    @NamedQuery(name = "AgentEntity.findByHost", query = "select a from AgentEntity a where a.hostId = :hostId"),
    @NamedQuery(name = "AgentEntity.findByKeyAndHost", query = "select a from AgentEntity a "
        + "where a.hostId = :hostId and a.keyThumbprint = :keyThumbprint"),
    @NamedQuery(name = "AgentEntity.findByUserCode", query = "select a from AgentEntity a where a.userCode = :userCode"),
    @NamedQuery(name = "AgentEntity.findByUserId", query = "select a from AgentEntity a where a.userId = :userId")
})
public class AgentEntity {

  @Id
  @Column(name = "ID", length = 36)
  private String id;

  @Column(name = "HOST_ID", length = 64, nullable = false)
  private String hostId;

  @Column(name = "KEY_THUMBPRINT", length = 64, nullable = false)
  private String keyThumbprint;

  @Column(name = "STATUS", length = 32, nullable = false)
  private String status;

  @Column(name = "PAYLOAD", columnDefinition = "TEXT", nullable = false)
  private String payload;

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

  /**
   * Queryable mirror of {@code payload.user_id}. For delegated agents this inherits from
   * {@code host.user_id} (AAP §3.2); for autonomous agents it is populated on claim (§2.10). Null
   * when unset. Written in lock-step with the payload by {@code JpaStorage.putAgent}.
   */
  @Column(name = "USER_ID", length = 36)
  private String userId;

  /**
   * Queryable mirror of {@code payload.user_code}, non-null only while the agent is in
   * {@code pending} state awaiting AAP §7.1 device-authorization approval. The /verify endpoints
   * look up the agent by this code.
   */
  @Column(name = "USER_CODE", length = 16)
  private String userCode;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getHostId() {
    return hostId;
  }

  public void setHostId(String hostId) {
    this.hostId = hostId;
  }

  public String getKeyThumbprint() {
    return keyThumbprint;
  }

  public void setKeyThumbprint(String keyThumbprint) {
    this.keyThumbprint = keyThumbprint;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
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

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getUserCode() {
    return userCode;
  }

  public void setUserCode(String userCode) {
    this.userCode = userCode;
  }
}
