package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "AGENT_AUTH_HOST", indexes = {
    @Index(name = "IDX_AGENT_AUTH_HOST_USER", columnList = "USER_ID")
})
@NamedQueries({
    @NamedQuery(name = "HostEntity.findByUserId", query = "select h from HostEntity h where h.userId = :userId")
})
public class HostEntity {

  @Id
  @Column(name = "ID", length = 64)
  private String id;

  @Column(name = "STATUS", length = 32, nullable = false)
  private String status;

  @Column(name = "PAYLOAD", columnDefinition = "TEXT", nullable = false)
  private String payload;

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

  /**
   * Queryable mirror of {@code payload.user_id}. Null when the host is not linked to a Keycloak
   * user. Written in lock-step with the payload by {@code JpaStorage.putHost}; used for the §2.6
   * user-deletion cascade lookup without scanning the JSON blob.
   */
  @Column(name = "USER_ID", length = 36)
  private String userId;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
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
}
