package com.github.chh.keycloak.agentauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

class JwksCacheTest {

  @Test
  void resolveCachesByUrlAndRefetchesOnKidMiss() throws Exception {
    try (CountingJwksServer server = CountingJwksServer.start("kid-a")) {
      JwksCache cache = new JwksCache(60_000, 10_000, 100);

      assertEquals("kid-a", cache.resolve(server.url(), "kid-a").get("kid"));
      assertEquals("kid-a", cache.resolve(server.url(), "kid-a").get("kid"));
      assertEquals(1, server.requestCount());

      server.rotate("kid-b");

      assertEquals("kid-b", cache.resolve(server.url(), "kid-b").get("kid"));
      assertEquals(2, server.requestCount());
    }
  }

  @Test
  void kidMissRefetchIsRateLimitedPerUrl() throws Exception {
    try (CountingJwksServer server = CountingJwksServer.start("kid-a")) {
      JwksCache cache = new JwksCache(60_000, 60_000, 100);

      assertEquals("kid-a", cache.resolve(server.url(), "kid-a").get("kid"));
      assertThrows(IllegalArgumentException.class, () -> cache.resolve(server.url(), "kid-c"));
      assertEquals(2, server.requestCount());

      assertThrows(IllegalArgumentException.class, () -> cache.resolve(server.url(), "kid-d"));
      assertEquals(2, server.requestCount());
    }
  }

  @Test
  void lookupHonorsTtlExpiry() throws Exception {
    try (CountingJwksServer server = CountingJwksServer.start("kid-a")) {
      JwksCache cache = new JwksCache(1, 10_000, 100);

      cache.resolve(server.url(), "kid-a");
      Thread.sleep(10);

      assertFalse(cache.lookup(server.url(), "kid-a").isPresent());
    }
  }

  @Test
  void sizeCapEvictsOldestUrlEntry() throws Exception {
    try (CountingJwksServer server = CountingJwksServer.start("kid-a")) {
      JwksCache cache = new JwksCache(60_000, 10_000, 1);

      assertTrue(cache.resolve(server.url("?one"), "kid-a").containsKey("kid"));
      assertTrue(cache.resolve(server.url("?two"), "kid-a").containsKey("kid"));

      assertEquals(1, cache.size());
    }
  }

  private static final class CountingJwksServer implements AutoCloseable {

    private final HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicReference<OctetKeyPair> key = new AtomicReference<>();
    private final AtomicReference<String> kid = new AtomicReference<>();

    private CountingJwksServer(HttpServer server) {
      this.server = server;
    }

    static CountingJwksServer start(String kid) throws Exception {
      HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      CountingJwksServer wrapper = new CountingJwksServer(server);
      wrapper.rotate(kid);
      server.createContext("/jwks", exchange -> {
        wrapper.requests.incrementAndGet();
        Map<String, Object> jwk = wrapper.key.get().toPublicJWK().toJSONObject();
        jwk.put("kid", wrapper.kid.get());
        byte[] response = JsonSerialization.writeValueAsString(Map.of("keys", List.of(jwk)))
            .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
      });
      server.start();
      return wrapper;
    }

    void rotate(String kid) {
      this.key.set(com.github.chh.keycloak.agentauth.support.TestKeys.generateEd25519());
      this.kid.set(kid);
    }

    String url() {
      return url("");
    }

    String url(String suffix) {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks" + suffix;
    }

    int requestCount() {
      return requests.get();
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }
}
