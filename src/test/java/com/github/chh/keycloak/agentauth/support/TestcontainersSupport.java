package com.github.chh.keycloak.agentauth.support;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

public final class TestcontainersSupport {

  private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.6.1";
  private static final String DOCKER_API_VERSION = "1.54";
  private static final String PROVIDER_LIBS_DIR = "target/provider-libs";
  private static final String TEST_REALM_IMPORT = "realms/agent-auth-test-realm.json";

  private TestcontainersSupport() {
  }

  public static KeycloakContainer newKeycloakContainer() {
    configureDockerEnvironment();
    return new KeycloakContainer(KEYCLOAK_IMAGE)
        .withProviderClassesFrom("target/classes")
        .withProviderLibsFrom(providerLibs())
        .withRealmImportFile(TEST_REALM_IMPORT);
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
    Path libsDir = Path.of(PROVIDER_LIBS_DIR);
    if (!Files.isDirectory(libsDir)) {
      throw new IllegalStateException(
          "Expected provider libs at " + libsDir.toAbsolutePath()
              + ". Run `mvn package` (or any later phase) to populate it via "
              + "maven-dependency-plugin:copy-dependencies.");
    }
    try (Stream<Path> paths = Files.list(libsDir)) {
      return paths
          .filter(path -> path.getFileName().toString().endsWith(".jar"))
          .map(Path::toFile)
          .toList();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to list provider libs in " + libsDir, e);
    }
  }
}
