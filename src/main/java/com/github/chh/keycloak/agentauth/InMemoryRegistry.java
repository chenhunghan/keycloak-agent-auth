package com.github.chh.keycloak.agentauth;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRegistry {
  public static final Map<String, Map<String, Object>> CAPABILITIES = new ConcurrentHashMap<>();
  public static final Map<String, Map<String, Object>> HOSTS = new ConcurrentHashMap<>();
  public static final Map<String, Map<String, Object>> AGENTS = new ConcurrentHashMap<>();
  public static final Map<String, Long> SEEN_JTIS = new ConcurrentHashMap<>();
}
