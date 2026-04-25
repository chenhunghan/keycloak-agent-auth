package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * Phase 6c: typed columns replace the prior JSON-blob {@code PAYLOAD}. Per-grant data lives in
 * {@code AGENT_AUTH_AGENT_GRANT} (Phase 3 secondary index); the per-agent grants list is also kept
 * here as JSON TEXT ({@code AGENT_GRANTS}) for the application read path that hasn't been swapped
 * to query the grants table yet.
 */
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

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

  @Column(name = "USER_ID", length = 36)
  private String userId;

  @Column(name = "USER_CODE", length = 16)
  private String userCode;

  @Column(name = "MODE", length = 32)
  private String mode;

  @Column(name = "NAME", length = 255)
  private String name;

  @Column(name = "AGENT_PUBLIC_KEY", columnDefinition = "TEXT")
  private String agentPublicKey;

  @Column(name = "AGENT_JWKS_URL", length = 2048)
  private String agentJwksUrl;

  @Column(name = "AGENT_KID", length = 255)
  private String agentKid;

  @Column(name = "ACTIVATED_AT", length = 64)
  private String activatedAt;

  @Column(name = "EXPIRES_AT", length = 64)
  private String expiresAt;

  @Column(name = "LAST_USED_AT", length = 64)
  private String lastUsedAt;

  @Column(name = "SESSION_TTL_RESET_AT")
  private Long sessionTtlResetAt;

  @Column(name = "MAX_LIFETIME_RESET_AT")
  private Long maxLifetimeResetAt;

  @Column(name = "ABSOLUTE_LIFETIME_ELAPSED")
  private Boolean absoluteLifetimeElapsed;

  @Column(name = "APPROVAL", columnDefinition = "TEXT")
  private String approval;

  @Column(name = "REASON", length = 1024)
  private String reason;

  @Column(name = "REJECTION_REASON", length = 1024)
  private String rejectionReason;

  @Column(name = "REVOCATION_REASON", length = 1024)
  private String revocationReason;

  @Column(name = "AGENT_GRANTS", columnDefinition = "TEXT")
  private String agentGrants;

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

  public String getMode() {
    return mode;
  }

  public void setMode(String mode) {
    this.mode = mode;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getAgentPublicKey() {
    return agentPublicKey;
  }

  public void setAgentPublicKey(String agentPublicKey) {
    this.agentPublicKey = agentPublicKey;
  }

  public String getAgentJwksUrl() {
    return agentJwksUrl;
  }

  public void setAgentJwksUrl(String agentJwksUrl) {
    this.agentJwksUrl = agentJwksUrl;
  }

  public String getAgentKid() {
    return agentKid;
  }

  public void setAgentKid(String agentKid) {
    this.agentKid = agentKid;
  }

  public String getActivatedAt() {
    return activatedAt;
  }

  public void setActivatedAt(String activatedAt) {
    this.activatedAt = activatedAt;
  }

  public String getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(String expiresAt) {
    this.expiresAt = expiresAt;
  }

  public String getLastUsedAt() {
    return lastUsedAt;
  }

  public void setLastUsedAt(String lastUsedAt) {
    this.lastUsedAt = lastUsedAt;
  }

  public Long getSessionTtlResetAt() {
    return sessionTtlResetAt;
  }

  public void setSessionTtlResetAt(Long sessionTtlResetAt) {
    this.sessionTtlResetAt = sessionTtlResetAt;
  }

  public Long getMaxLifetimeResetAt() {
    return maxLifetimeResetAt;
  }

  public void setMaxLifetimeResetAt(Long maxLifetimeResetAt) {
    this.maxLifetimeResetAt = maxLifetimeResetAt;
  }

  public Boolean getAbsoluteLifetimeElapsed() {
    return absoluteLifetimeElapsed;
  }

  public void setAbsoluteLifetimeElapsed(Boolean absoluteLifetimeElapsed) {
    this.absoluteLifetimeElapsed = absoluteLifetimeElapsed;
  }

  public String getApproval() {
    return approval;
  }

  public void setApproval(String approval) {
    this.approval = approval;
  }

  public String getReason() {
    return reason;
  }

  public void setReason(String reason) {
    this.reason = reason;
  }

  public String getRejectionReason() {
    return rejectionReason;
  }

  public void setRejectionReason(String rejectionReason) {
    this.rejectionReason = rejectionReason;
  }

  public String getRevocationReason() {
    return revocationReason;
  }

  public void setRevocationReason(String revocationReason) {
    this.revocationReason = revocationReason;
  }

  public String getAgentGrants() {
    return agentGrants;
  }

  public void setAgentGrants(String agentGrants) {
    this.agentGrants = agentGrants;
  }
}
