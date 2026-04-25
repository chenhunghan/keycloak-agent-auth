package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * Phase 6b: typed columns replace the prior JSON-blob {@code PAYLOAD}. The Ed25519 JWK is kept as
 * TEXT ({@code PUBLIC_KEY_JWK}) — we never query its components individually — and the
 * default-grants list is similarly serialized JSON ({@code DEFAULT_CAPABILITY_GRANTS}); both could
 * be normalized further in a follow-up if a query pattern justifies it.
 */
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

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

  @Column(name = "USER_ID", length = 36)
  private String userId;

  @Column(name = "PUBLIC_KEY_JWK", columnDefinition = "TEXT")
  private String publicKeyJwk;

  @Column(name = "HOST_JWKS_URL", length = 2048)
  private String hostJwksUrl;

  @Column(name = "HOST_KID", length = 255)
  private String hostKid;

  @Column(name = "NAME", length = 255)
  private String name;

  @Column(name = "DESCRIPTION", length = 1024)
  private String description;

  @Column(name = "SERVICE_ACCOUNT_CLIENT_ID", length = 255)
  private String serviceAccountClientId;

  @Column(name = "DEFAULT_CAPABILITY_GRANTS", columnDefinition = "TEXT")
  private String defaultCapabilityGrants;

  @Column(name = "LAST_USED_AT", length = 64)
  private String lastUsedAt;

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

  public String getPublicKeyJwk() {
    return publicKeyJwk;
  }

  public void setPublicKeyJwk(String publicKeyJwk) {
    this.publicKeyJwk = publicKeyJwk;
  }

  public String getHostJwksUrl() {
    return hostJwksUrl;
  }

  public void setHostJwksUrl(String hostJwksUrl) {
    this.hostJwksUrl = hostJwksUrl;
  }

  public String getHostKid() {
    return hostKid;
  }

  public void setHostKid(String hostKid) {
    this.hostKid = hostKid;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getServiceAccountClientId() {
    return serviceAccountClientId;
  }

  public void setServiceAccountClientId(String serviceAccountClientId) {
    this.serviceAccountClientId = serviceAccountClientId;
  }

  public String getDefaultCapabilityGrants() {
    return defaultCapabilityGrants;
  }

  public void setDefaultCapabilityGrants(String defaultCapabilityGrants) {
    this.defaultCapabilityGrants = defaultCapabilityGrants;
  }

  public String getLastUsedAt() {
    return lastUsedAt;
  }

  public void setLastUsedAt(String lastUsedAt) {
    this.lastUsedAt = lastUsedAt;
  }
}
