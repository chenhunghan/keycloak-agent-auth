package com.github.chh.keycloak.agentauth;

import java.time.Instant;
import java.util.Map;

/**
 * Centralised lifecycle-clock evaluator for agent records.
 *
 * <p>
 * AAP §§2.3, 2.4, 2.5 define three independent clocks per agent:
 *
 * <ul>
 * <li><b>Session TTL</b> — short-lived window represented by {@code expires_at}; when it elapses
 * the agent transitions to {@code expired} and may be reactivated.</li>
 * <li><b>Max lifetime</b> — bounded by {@code max_lifetime_seconds} measured from the most recent
 * reactivation point ({@code max_lifetime_reset_at}, falling back to {@code created_at}); when it
 * elapses the agent transitions to {@code expired} and may be reactivated.</li>
 * <li><b>Absolute lifetime</b> — bounded by {@code absolute_lifetime_seconds} measured from
 * {@code created_at}; when it elapses the agent transitions to permanent {@code revoked} and MUST
 * NOT be reactivated.</li>
 * </ul>
 *
 * <p>
 * Status, reactivate, execute and introspect all need the same answer. Concentrating the logic here
 * keeps every flow in lock-step with the spec and avoids ad-hoc divergence.
 *
 * <p>
 * Backward compatibility: the legacy {@code absolute_lifetime_elapsed} boolean flag (set by the
 * admin force-expire endpoint and used by tests to simulate absolute-lifetime exhaustion without
 * time travel) is honoured as a hard signal — if the flag is true, evaluation always returns
 * {@link Result#ABSOLUTE_LIFETIME_EXCEEDED} regardless of timestamps.
 */
final class LifecycleClock {

  /** Outcome of clock evaluation against an agent record. */
  enum Result {
    /** No clock has elapsed; the record's stored status should stand. */
    ACTIVE,
    /** Session TTL ({@code expires_at}) has elapsed; agent is {@code expired}. */
    SESSION_EXPIRED,
    /** Max lifetime has elapsed since the last reset; agent is {@code expired}. */
    MAX_LIFETIME_EXPIRED,
    /** Absolute lifetime has elapsed since creation; agent is permanently {@code revoked}. */
    ABSOLUTE_LIFETIME_EXCEEDED
  }

  private LifecycleClock() {
    // utility
  }

  /**
   * Evaluates the lifecycle clocks against the supplied agent record.
   *
   * <p>
   * Pure: no mutation, no I/O. Returns the elapsed clock with the highest severity
   * ({@code ABSOLUTE_LIFETIME_EXCEEDED} > {@code MAX_LIFETIME_EXPIRED} > {@code SESSION_EXPIRED}).
   *
   * @param agentData
   *          the in-memory agent record (must not be {@code null})
   * @return the most severe clock that has elapsed, or {@link Result#ACTIVE} if all clocks hold
   */
  static Result evaluate(Map<String, Object> agentData) {
    if (agentData == null) {
      return Result.ACTIVE;
    }

    // Hard override: legacy admin flag wins. Tests rely on this to simulate
    // absolute-lifetime exhaustion without moving the wall clock.
    if (Boolean.TRUE.equals(agentData.get("absolute_lifetime_elapsed"))) {
      return Result.ABSOLUTE_LIFETIME_EXCEEDED;
    }

    long now = System.currentTimeMillis();

    // Absolute lifetime — measured from created_at, never reset.
    Long absoluteLifetimeSeconds = readSeconds(agentData, "absolute_lifetime_seconds");
    Instant createdAt = parseInstant(agentData.get("created_at"));
    if (absoluteLifetimeSeconds != null && createdAt != null) {
      long deadline = createdAt.toEpochMilli() + absoluteLifetimeSeconds * 1000L;
      if (now >= deadline) {
        return Result.ABSOLUTE_LIFETIME_EXCEEDED;
      }
    }

    // Max lifetime — measured from the most recent reactivation point. Falls back to
    // created_at when the agent has never been reactivated.
    Long maxLifetimeSeconds = readSeconds(agentData, "max_lifetime_seconds");
    if (maxLifetimeSeconds != null) {
      Long maxResetAt = readEpochMillis(agentData, "max_lifetime_reset_at");
      Long createdAtMillis = createdAt != null ? createdAt.toEpochMilli() : null;
      Long anchor = maxResetAt != null ? maxResetAt : createdAtMillis;
      if (anchor != null) {
        long deadline = anchor + maxLifetimeSeconds * 1000L;
        if (now >= deadline) {
          return Result.MAX_LIFETIME_EXPIRED;
        }
      }
    }

    // Session TTL — represented directly by expires_at.
    Instant expiresAt = parseInstant(agentData.get("expires_at"));
    if (expiresAt != null && now >= expiresAt.toEpochMilli()) {
      return Result.SESSION_EXPIRED;
    }

    return Result.ACTIVE;
  }

  /**
   * Mutates {@code agentData}'s status if a clock has elapsed and the agent isn't already in a
   * terminal state. Caller decides whether to persist.
   *
   * <p>
   * If {@link #evaluate(Map)} returns {@link Result#ABSOLUTE_LIFETIME_EXCEEDED}, sets
   * {@code status=revoked} and stamps {@code revocation_reason=absolute_lifetime_exceeded}. For the
   * two expired-class results sets {@code status=expired}. Already-terminal records
   * ({@code revoked}, {@code rejected}, {@code claimed}) are left untouched.
   *
   * @param agentData
   *          the in-memory agent record (must not be {@code null})
   * @return the {@link Result} returned by {@link #evaluate(Map)}
   */
  static Result applyExpiry(Map<String, Object> agentData) {
    Result result = evaluate(agentData);
    if (agentData == null || result == Result.ACTIVE) {
      return result;
    }
    String status = agentData.get("status") instanceof String s ? s : null;
    // Don't overwrite terminal states; revoked/rejected/claimed are immutable per §2.6/§2.10.
    if ("revoked".equals(status) || "rejected".equals(status) || "claimed".equals(status)) {
      return result;
    }
    if (result == Result.ABSOLUTE_LIFETIME_EXCEEDED) {
      agentData.put("status", "revoked");
      agentData.putIfAbsent("revocation_reason", "absolute_lifetime_exceeded");
    } else {
      agentData.put("status", "expired");
    }
    return result;
  }

  private static Long readSeconds(Map<String, Object> agentData, String key) {
    Object value = agentData.get(key);
    if (value instanceof Number n) {
      long s = n.longValue();
      return s > 0 ? s : null;
    }
    if (value instanceof String s && !s.isBlank()) {
      try {
        long parsed = Long.parseLong(s.trim());
        return parsed > 0 ? parsed : null;
      } catch (NumberFormatException ignored) {
        return null;
      }
    }
    return null;
  }

  private static Long readEpochMillis(Map<String, Object> agentData, String key) {
    Object value = agentData.get(key);
    if (value instanceof Number n) {
      return n.longValue();
    }
    if (value instanceof String s && !s.isBlank()) {
      try {
        return Long.parseLong(s.trim());
      } catch (NumberFormatException ignored) {
        return null;
      }
    }
    return null;
  }

  private static Instant parseInstant(Object value) {
    if (value instanceof String s && !s.isBlank()) {
      try {
        return Instant.parse(s);
      } catch (Exception ignored) {
        return null;
      }
    }
    if (value instanceof Number n) {
      return Instant.ofEpochMilli(n.longValue());
    }
    return null;
  }
}
