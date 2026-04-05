package com.github.chh.keycloak.agentauth;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * JAX-RS response filter that adds {@code Cache-Control: max-age=3600} to the Agent Auth Protocol
 * discovery endpoint ({@code /.well-known/agent-configuration}).
 *
 * <p>
 * Per spec §5.1, servers SHOULD include a {@code Cache-Control} header with a recommended
 * {@code max-age} of 3600 seconds on the discovery response.
 */
@Provider
public class AgentAuthDiscoveryCacheFilter implements ContainerResponseFilter {

  private static final String AGENT_CONFIGURATION_PATH = ".well-known/agent-configuration";

  @Override
  public void filter(ContainerRequestContext requestContext,
      ContainerResponseContext responseContext) throws IOException {
    String path = requestContext.getUriInfo().getPath();
    if (path != null && path.endsWith(AGENT_CONFIGURATION_PATH)) {
      responseContext.getHeaders().putSingle("Cache-Control", "max-age=3600, public");
    }
  }
}
