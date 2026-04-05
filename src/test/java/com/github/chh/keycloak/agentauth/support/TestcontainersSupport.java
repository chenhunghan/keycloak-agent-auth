package com.github.chh.keycloak.agentauth.support;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public final class TestcontainersSupport {

  private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.1.4";
  private static final String DOCKER_API_VERSION = "1.54";

  private TestcontainersSupport() {
  }

  public static KeycloakContainer newKeycloakContainer() {
    configureDockerEnvironment();
    return new KeycloakContainer(KEYCLOAK_IMAGE)
        .withProviderClassesFrom("target/classes")
        .withProviderLibsFrom(providerLibs());
  }

  private static void configureDockerEnvironment() {
    String dockerHost = System.getenv("DOCKER_HOST");
    if (dockerHost == null || dockerHost.isBlank()) {
      return;
    }

    Path preferredSocket = Path.of(System.getProperty("user.home"), ".docker", "run",
        "docker.sock");
    if (Files.exists(preferredSocket)) {
      dockerHost = "unix://" + preferredSocket;
    }

    System.setProperty("DOCKER_HOST", dockerHost);
    System.setProperty("docker.host", dockerHost);
    System.setProperty("DOCKER_API_VERSION", DOCKER_API_VERSION);
    System.setProperty("api.version", DOCKER_API_VERSION);
    System.setProperty("TESTCONTAINERS_RYUK_DISABLED", "true");
    System.setProperty("ryuk.disabled", "true");

    if (dockerHost.startsWith("unix://")) {
      String socketPath = dockerHost.substring("unix://".length());
      System.setProperty("docker.socket.override", socketPath);
      System.setProperty("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", socketPath);
    }
  }

  private static List<File> providerLibs() {
    List<File> libs = new ArrayList<>();
    libs.addAll(findJars("com", "nimbusds", "nimbus-jose-jwt"));
    libs.addAll(findJars("com", "google", "crypto", "tink", "tink"));

    return libs;
  }

  private static List<File> findJars(String... pathParts) {
    List<File> jars = new ArrayList<>();
    String[] segments = new String[pathParts.length + 2];
    segments[0] = ".m2";
    segments[1] = "repository";
    System.arraycopy(pathParts, 0, segments, 2, pathParts.length);
    Path dir = Path.of(System.getProperty("user.home"), segments);
    if (!Files.exists(dir)) {
      return jars;
    }

    try (Stream<Path> paths = Files.walk(dir)) {
      paths.filter(path -> path.getFileName().toString().endsWith(".jar"))
          .map(Path::toFile)
          .forEach(jars::add);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to locate provider runtime libraries", e);
    }

    return jars;
  }
}
