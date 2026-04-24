package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Periodic sweep of pending agents whose {@code pending} state has outlived the configured
 * threshold (AAP §7.1). Scheduled once per JVM — piggy-backs on the same postInit hook the
 * user-deletion cascade uses.
 *
 * <p>
 * The sweep iterates every realm, resolves {@link AgentAuthStorage} in a fresh Keycloak session,
 * and invokes {@link AgentAuthStorage#deletePendingAgentsOlderThan(long)}. All mutations run inside
 * the per-realm {@link KeycloakModelUtils#runJobInTransaction runJobInTransaction} boundary so
 * rollbacks are clean. Exceptions are logged; one realm's failure does not block the rest.
 */
public final class PendingAgentCleanup {

  public static final long DEFAULT_THRESHOLD_SECONDS = 24L * 60 * 60; // 24 hours
  public static final long DEFAULT_INTERVAL_SECONDS = 60L * 60; // 1 hour

  private static final Logger LOG = Logger.getLogger(PendingAgentCleanup.class.getName());

  private static ScheduledExecutorService SCHEDULER;

  private PendingAgentCleanup() {
  }

  /**
   * Start the background sweep. Idempotent — subsequent calls are no-ops. Uses a single daemon
   * thread so JVM shutdown isn't blocked.
   */
  public static synchronized void start(KeycloakSessionFactory factory,
      long intervalSeconds, long thresholdSeconds) {
    if (SCHEDULER != null) {
      return;
    }
    SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "agent-auth-pending-cleanup");
      t.setDaemon(true);
      return t;
    });
    SCHEDULER.scheduleAtFixedRate(
        () -> runSweep(factory, thresholdSeconds),
        intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
  }

  /** Run one sweep across every realm. Exposed for tests and for the admin trigger. */
  public static int runSweep(KeycloakSessionFactory factory, long thresholdSeconds) {
    long thresholdMs = System.currentTimeMillis() - (thresholdSeconds * 1000L);
    int totalRemoved = 0;
    try {
      for (String realmName : realmNames(factory)) {
        int removed = sweepRealm(factory, realmName, thresholdMs);
        totalRemoved += removed;
      }
    } catch (RuntimeException e) {
      LOG.log(Level.WARNING, "agent-auth: pending-agent sweep failed", e);
    }
    return totalRemoved;
  }

  private static java.util.List<String> realmNames(KeycloakSessionFactory factory) {
    java.util.List<String> names = new java.util.ArrayList<>();
    KeycloakModelUtils.runJobInTransaction(factory, session -> session.realms().getRealmsStream()
        .map(RealmModel::getName).forEach(names::add));
    return names;
  }

  private static int sweepRealm(KeycloakSessionFactory factory, String realmName,
      long thresholdMs) {
    int[] removed = {0};
    KeycloakModelUtils.runJobInTransaction(factory, (KeycloakSession session) -> {
      RealmModel realm = session.realms().getRealmByName(realmName);
      if (realm == null) {
        return;
      }
      session.getContext().setRealm(realm);
      AgentAuthStorage storage;
      try {
        storage = session.getProvider(AgentAuthStorage.class);
      } catch (RuntimeException e) {
        LOG.log(Level.FINE,
            () -> "agent-auth: storage unavailable for realm " + realmName
                + "; skipping pending-agent sweep");
        return;
      }
      if (storage == null) {
        return;
      }
      removed[0] = storage.deletePendingAgentsOlderThan(thresholdMs);
      if (removed[0] > 0) {
        LOG.log(Level.INFO, () -> "agent-auth: swept " + removed[0]
            + " pending agent(s) in realm " + realmName);
      }
    });
    return removed[0];
  }
}
