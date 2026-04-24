package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Cascades Agent Auth Protocol §2.6: "When a user account is deleted, the server MUST revoke all
 * hosts linked to that user and cascade revocation to all agents under those hosts."
 *
 * <p>
 * <b>SPI choice.</b> Keycloak exposes two distinct event buses:
 * <ul>
 * <li>{@link EventListenerProvider} — user-observable authentication events (LOGIN, REGISTER, etc.)
 * surfaced as {@link org.keycloak.events.Event} with an {@link org.keycloak.events.EventType}.
 * Convenient for audit log sinks, but <b>never dispatches
 * {@link UserModel.UserRemovedEvent}</b>.</li>
 * <li>{@link KeycloakSessionFactory#register(org.keycloak.provider.ProviderEventListener)} —
 * internal model events like {@code UserModel.UserRemovedEvent}, which extends
 * {@link org.keycloak.provider.ProviderEvent}. This is how Keycloak itself wires up
 * authorization-data cleanup on user deletion (see
 * {@code org.keycloak.authorization.store.AuthorizationStoreFactory#registerSynchronizationListeners}
 * and {@code org.keycloak.authorization.store.syncronization.UserSynchronizer} in
 * keycloak-server-spi-private).</li>
 * </ul>
 * We therefore piggy-back on the stable {@link EventListenerProviderFactory} SPI purely as a
 * deployment handle — its {@link #postInit(KeycloakSessionFactory) postInit} hook gives us a
 * reference to the session factory on which we can {@code register} a
 * {@link org.keycloak.provider.ProviderEventListener} that filters for
 * {@code UserModel.UserRemovedEvent}. The {@link EventListenerProvider#onEvent(Event)
 * EventListenerProvider.onEvent} overloads stay no-op; nothing on that bus is relevant to us.
 *
 * <p>
 * <b>Transaction semantics.</b> The cascade runs on the same {@link KeycloakSession} that
 * dispatched the user-removed event (obtained from {@code event.getKeycloakSession()}). All
 * {@code AgentAuthStorage} mutations therefore participate in the admin REST call's JPA transaction
 * — they commit atomically with the user row's DELETE, or roll back together if the delete fails.
 *
 * <p>
 * <b>Realm scoping.</b> Because we register one global listener, every realm's user deletions pass
 * through here. Realms that haven't provisioned agent-auth state will simply find an empty
 * {@code findHostsByUser} result, which is a no-op. If the {@code AgentAuthStorage} provider is
 * unavailable for a realm we log and bail — we never throw back into Keycloak's deletion path.
 */
public class AgentAuthUserEventListenerProviderFactory implements EventListenerProviderFactory {

  public static final String ID = "agent-auth-user-cascade";

  private static final Logger LOG = Logger
      .getLogger(AgentAuthUserEventListenerProviderFactory.class.getName());

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    // The log-event SPI is not what carries UserRemovedEvent — return a do-nothing
    // EventListenerProvider purely to satisfy the SPI contract.
    return NoOpEventListenerProvider.INSTANCE;
  }

  @Override
  public void init(Scope config) {
    // no-op
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(providerEvent -> {
      if (providerEvent instanceof UserModel.UserRemovedEvent removed) {
        try {
          handleUserRemoved(removed);
        } catch (RuntimeException e) {
          // Never propagate — a failure here must not abort the user delete transaction
          // for reasons unrelated to agent-auth state.
          LOG.log(Level.WARNING,
              "agent-auth: user-deletion cascade failed; continuing", e);
        }
      }
    });
    // AAP §7.1 pending-agent GC. Piggy-backing on this factory because it already owns the
    // postInit hook; the scheduler itself is idempotent across repeated postInit calls.
    PendingAgentCleanup.start(factory,
        PendingAgentCleanup.DEFAULT_INTERVAL_SECONDS,
        PendingAgentCleanup.DEFAULT_THRESHOLD_SECONDS);
  }

  @Override
  public void close() {
    // no-op
  }

  @Override
  public String getId() {
    return ID;
  }

  /**
   * Revoke all hosts linked to the removed user's id and cascade revocation to non-terminal agents
   * under each host. Mirrors the terminal-state handling of
   * {@code AgentAuthAdminResourceProvider#unlinkHost} so claimed/revoked/rejected records are left
   * alone.
   */
  private static void handleUserRemoved(UserModel.UserRemovedEvent event) {
    RealmModel realm = event.getRealm();
    KeycloakSession session = event.getKeycloakSession();
    UserModel user = event.getUser();
    if (realm == null || session == null || user == null) {
      return;
    }
    String userId = user.getId();
    if (userId == null) {
      return;
    }

    AgentAuthStorage storage;
    try {
      storage = session.getProvider(AgentAuthStorage.class);
    } catch (RuntimeException e) {
      // Realm doesn't have agent-auth wired in — nothing to cascade.
      LOG.log(Level.FINE,
          () -> "agent-auth: storage provider unavailable for realm "
              + realm.getName() + "; skipping user-removed cascade");
      return;
    }
    if (storage == null) {
      return;
    }

    List<Map<String, Object>> linkedHosts = storage.findHostsByUser(userId);
    if (linkedHosts.isEmpty()) {
      return;
    }

    String nowTs = Instant.now().toString();
    for (Map<String, Object> hostData : linkedHosts) {
      String hostId = (String) hostData.get("host_id");
      if (hostId == null) {
        continue;
      }
      revokeAgentsUnder(storage, hostId, nowTs);
      revokeHost(storage, hostId, hostData, nowTs);
    }
  }

  private static void revokeAgentsUnder(AgentAuthStorage storage, String hostId, String nowTs) {
    for (Map<String, Object> agentData : storage.findAgentsByHost(hostId)) {
      String agentId = (String) agentData.get("agent_id");
      if (agentId == null) {
        continue;
      }
      String status = (String) agentData.get("status");
      if (isTerminal(status)) {
        // §2.10: claimed/revoked/rejected are terminal — leave untouched. Matches the
        // terminal-state check in AgentAuthAdminResourceProvider#unlinkHost.
        continue;
      }
      agentData.put("status", "revoked");
      agentData.put("updated_at", nowTs);
      storage.putAgent(agentId, agentData);
    }
  }

  private static void revokeHost(AgentAuthStorage storage, String hostId,
      Map<String, Object> hostData, String nowTs) {
    String status = (String) hostData.get("status");
    if (isTerminal(status)) {
      return;
    }
    hostData.put("status", "revoked");
    hostData.put("updated_at", nowTs);
    storage.putHost(hostId, hostData);
  }

  private static boolean isTerminal(String status) {
    return "claimed".equals(status) || "revoked".equals(status) || "rejected".equals(status);
  }

  /**
   * Stateless no-op; the real work happens in the {@code ProviderEventListener} registered in
   * {@link AgentAuthUserEventListenerProviderFactory#postInit(KeycloakSessionFactory)}.
   */
  private static final class NoOpEventListenerProvider implements EventListenerProvider {

    static final NoOpEventListenerProvider INSTANCE = new NoOpEventListenerProvider();

    @Override
    public void onEvent(Event event) {
      // no-op
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
      // no-op
    }

    @Override
    public void close() {
      // no-op
    }
  }
}
