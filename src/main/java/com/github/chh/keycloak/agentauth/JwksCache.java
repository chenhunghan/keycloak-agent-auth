package com.github.chh.keycloak.agentauth;

import com.fasterxml.jackson.core.type.TypeReference;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.util.JsonSerialization;

final class JwksCache {

  private static final long TTL_MS = 5 * 60 * 1000L;
  private static final long REFRESH_MISS_WINDOW_MS = 10_000L;
  private static final int MAX_ENTRIES = 1_000;

  private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
  private final long ttlMs;
  private final long refreshMissWindowMs;
  private final int maxEntries;

  JwksCache() {
    this(TTL_MS, REFRESH_MISS_WINDOW_MS, MAX_ENTRIES);
  }

  JwksCache(long ttlMs, long refreshMissWindowMs, int maxEntries) {
    this.ttlMs = ttlMs;
    this.refreshMissWindowMs = refreshMissWindowMs;
    this.maxEntries = maxEntries;
  }

  Optional<Map<String, Object>> lookup(String jwksUrl, String kid) {
    Entry entry = entries.get(jwksUrl);
    long now = System.currentTimeMillis();
    if (entry == null || now - entry.fetchedAtMs >= ttlMs) {
      return Optional.empty();
    }
    Map<String, Object> key = entry.keysByKid.get(kid);
    return key == null ? Optional.empty() : Optional.of(new HashMap<>(key));
  }

  Map<String, Object> resolve(String jwksUrl, String kid) {
    long now = System.currentTimeMillis();
    Entry entry = entries.get(jwksUrl);
    if (entry == null || now - entry.fetchedAtMs >= ttlMs) {
      entry = fetchAndStore(jwksUrl, now, 0);
    }

    Map<String, Object> key = entry.keysByKid.get(kid);
    if (key != null) {
      return new HashMap<>(key);
    }

    if (now - entry.lastRefetchAtMs >= refreshMissWindowMs) {
      entry = fetchAndStore(jwksUrl, now, now);
      key = entry.keysByKid.get(kid);
      if (key != null) {
        return new HashMap<>(key);
      }
    }

    throw new IllegalArgumentException("No matching JWK found for kid");
  }

  /**
   * Returns every JWK currently published at {@code jwksUrl}, keyed by {@code kid}. Used by the
   * §4.5 host-rotation fallback in {@link AgentJwtVerifier}: the agent JWT's {@code iss} is the
   * host-key thumbprint, not the kid, so callers need to scan all published keys looking for a
   * matching thumbprint rather than indexing by kid. Re-fetches a stale entry on miss.
   */
  Map<String, Map<String, Object>> resolveAll(String jwksUrl) {
    long now = System.currentTimeMillis();
    Entry entry = entries.get(jwksUrl);
    if (entry == null || now - entry.fetchedAtMs >= ttlMs) {
      entry = fetchAndStore(jwksUrl, now, 0);
    }
    Map<String, Map<String, Object>> copy = new HashMap<>();
    for (Map.Entry<String, Map<String, Object>> e : entry.keysByKid.entrySet()) {
      copy.put(e.getKey(), new HashMap<>(e.getValue()));
    }
    return copy;
  }

  void invalidate(String jwksUrl) {
    entries.remove(jwksUrl);
  }

  int size() {
    return entries.size();
  }

  private Entry fetchAndStore(String jwksUrl, long now, long lastRefetchAtMs) {
    Map<String, Map<String, Object>> keysByKid = fetchJwks(jwksUrl);
    Entry entry = new Entry(keysByKid, now, lastRefetchAtMs);
    entries.put(jwksUrl, entry);
    evictOverflow();
    return entry;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Map<String, Object>> fetchJwks(String jwksUrl) {
    try {
      URI uri = URI.create(jwksUrl);
      String scheme = uri.getScheme();
      if (!"https".equalsIgnoreCase(scheme) && !isLocalJwksUri(uri)) {
        throw new IllegalArgumentException("JWKS URL must use HTTPS");
      }

      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("Accept", "application/json");
      conn.setConnectTimeout(5_000);
      conn.setReadTimeout(5_000);

      int status = conn.getResponseCode();
      if (status != 200) {
        throw new IllegalArgumentException("Unable to fetch JWKS");
      }

      try (InputStream is = conn.getInputStream()) {
        Map<String, Object> jwks = JsonSerialization.readValue(is,
            new TypeReference<Map<String, Object>>() {
            });
        Object rawKeys = jwks.get("keys");
        if (!(rawKeys instanceof Iterable<?> keys)) {
          throw new IllegalArgumentException("JWKS does not contain a keys array");
        }

        Map<String, Map<String, Object>> keysByKid = new HashMap<>();
        for (Object rawKey : keys) {
          if (rawKey instanceof Map<?, ?> key && key.get("kid") instanceof String kid) {
            keysByKid.put(kid, new HashMap<>((Map<String, Object>) key));
          }
        }
        return keysByKid;
      }
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalArgumentException("Unable to resolve JWKS key: " + e.getMessage(), e);
    }
  }

  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  private static boolean isLocalJwksUri(URI uri) {
    if (!"http".equalsIgnoreCase(uri.getScheme())) {
      return false;
    }
    String host = uri.getHost();
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "host.testcontainers.internal".equalsIgnoreCase(host)
        || "host.docker.internal".equalsIgnoreCase(host)
        || "172.17.0.1".equals(host);
  }

  private void evictOverflow() {
    if (entries.size() <= maxEntries) {
      return;
    }
    entries.entrySet().stream()
        .min(Comparator.comparingLong(entry -> entry.getValue().fetchedAtMs))
        .ifPresent(oldest -> entries.remove(oldest.getKey()));
  }

  private record Entry(
      Map<String, Map<String, Object>> keysByKid,
      long fetchedAtMs,
      long lastRefetchAtMs) {
  }
}
