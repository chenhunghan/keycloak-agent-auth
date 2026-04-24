package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "AGENT_AUTH_HOST")
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
}
