package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "AGENT_AUTH_ROTATED_HOST")
public class RotatedHostEntity {

  @Id
  @Column(name = "OLD_HOST_ID", length = 64)
  private String oldHostId;

  @Column(name = "NEW_HOST_ID", length = 64, nullable = false)
  private String newHostId;

  @Column(name = "ROTATED_AT", nullable = false)
  private long rotatedAt;

  public String getOldHostId() {
    return oldHostId;
  }

  public void setOldHostId(String oldHostId) {
    this.oldHostId = oldHostId;
  }

  public String getNewHostId() {
    return newHostId;
  }

  public void setNewHostId(String newHostId) {
    this.newHostId = newHostId;
  }

  public long getRotatedAt() {
    return rotatedAt;
  }

  public void setRotatedAt(long rotatedAt) {
    this.rotatedAt = rotatedAt;
  }
}
