package com.github.chh.keycloak.agentauth.storage.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * Phase 6a: typed columns replace the prior JSON-blob {@code PAYLOAD}. Indexed columns
 * ({@code ORGANIZATION_ID}, {@code REQUIRED_ROLE}) support Phase 1's user-entitlement filter and
 * Phase 4's eager cascade. Schema-shaped fields ({@code INPUT_SCHEMA}, {@code OUTPUT_SCHEMA})
 * remain serialized JSON since they're recursive.
 */
@Entity
@Table(name = "AGENT_AUTH_CAPABILITY", indexes = {
    @Index(name = "IDX_AGENT_AUTH_CAPABILITY_ORG", columnList = "ORGANIZATION_ID"),
    @Index(name = "IDX_AGENT_AUTH_CAPABILITY_ROLE", columnList = "REQUIRED_ROLE")
})
public class CapabilityEntity {

  @Id
  @Column(name = "NAME", length = 255)
  private String name;

  @Column(name = "DESCRIPTION", length = 1024)
  private String description;

  @Column(name = "LOCATION", length = 2048)
  private String location;

  @Column(name = "VISIBILITY", length = 32)
  private String visibility;

  @Column(name = "REQUIRES_APPROVAL")
  private Boolean requiresApproval;

  @Column(name = "AUTO_DENY")
  private Boolean autoDeny;

  @Column(name = "WRITE_CAPABLE")
  private Boolean writeCapable;

  @Column(name = "ORGANIZATION_ID", length = 36)
  private String organizationId;

  @Column(name = "REQUIRED_ROLE", length = 255)
  private String requiredRole;

  @Column(name = "INPUT_SCHEMA", columnDefinition = "TEXT")
  private String inputSchema;

  @Column(name = "OUTPUT_SCHEMA", columnDefinition = "TEXT")
  private String outputSchema;

  @Column(name = "CREATED_AT", nullable = false)
  private long createdAt;

  @Column(name = "UPDATED_AT", nullable = false)
  private long updatedAt;

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

  public String getLocation() {
    return location;
  }

  public void setLocation(String location) {
    this.location = location;
  }

  public String getVisibility() {
    return visibility;
  }

  public void setVisibility(String visibility) {
    this.visibility = visibility;
  }

  public Boolean getRequiresApproval() {
    return requiresApproval;
  }

  public void setRequiresApproval(Boolean requiresApproval) {
    this.requiresApproval = requiresApproval;
  }

  public Boolean getAutoDeny() {
    return autoDeny;
  }

  public void setAutoDeny(Boolean autoDeny) {
    this.autoDeny = autoDeny;
  }

  public Boolean getWriteCapable() {
    return writeCapable;
  }

  public void setWriteCapable(Boolean writeCapable) {
    this.writeCapable = writeCapable;
  }

  public String getOrganizationId() {
    return organizationId;
  }

  public void setOrganizationId(String organizationId) {
    this.organizationId = organizationId;
  }

  public String getRequiredRole() {
    return requiredRole;
  }

  public void setRequiredRole(String requiredRole) {
    this.requiredRole = requiredRole;
  }

  public String getInputSchema() {
    return inputSchema;
  }

  public void setInputSchema(String inputSchema) {
    this.inputSchema = inputSchema;
  }

  public String getOutputSchema() {
    return outputSchema;
  }

  public void setOutputSchema(String outputSchema) {
    this.outputSchema = outputSchema;
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
