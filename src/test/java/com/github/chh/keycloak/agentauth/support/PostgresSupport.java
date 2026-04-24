package com.github.chh.keycloak.agentauth.support;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Postgres-backed Keycloak testcontainer setup for E2E tests that need state to survive across
 * Keycloak restarts.
 */
public final class PostgresSupport {

  static final String POSTGRES_IMAGE = "postgres:18-alpine";
  static final String POSTGRES_ALIAS = "agent-auth-postgres";
  static final String DB_NAME = "keycloak";
  static final String DB_USER = "keycloak";
  static final String DB_PASSWORD = "keycloak";

  private PostgresSupport() {
  }

  @SuppressWarnings("resource")
  public static PostgreSQLContainer newPostgres(Network network) {
    return new PostgreSQLContainer(POSTGRES_IMAGE)
        .withDatabaseName(DB_NAME)
        .withUsername(DB_USER)
        .withPassword(DB_PASSWORD)
        .withNetwork(network)
        .withNetworkAliases(POSTGRES_ALIAS);
  }

  /**
   * Create a Keycloak container wired to the given Postgres container over {@code network}.
   * Postgres must already be started (we read the internal port via the network alias).
   */
  public static KeycloakContainer newKeycloakOnPostgres(Network network) {
    String jdbcUrl = "jdbc:postgresql://" + POSTGRES_ALIAS + ":5432/" + DB_NAME;
    return TestcontainersSupport.newKeycloakContainer()
        .withNetwork(network)
        .withEnv("KC_DB", "postgres")
        .withEnv("KC_DB_URL", jdbcUrl)
        .withEnv("KC_DB_USERNAME", DB_USER)
        .withEnv("KC_DB_PASSWORD", DB_PASSWORD);
  }
}
