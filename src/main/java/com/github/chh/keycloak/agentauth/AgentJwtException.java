package com.github.chh.keycloak.agentauth;

import jakarta.ws.rs.core.Response;

/**
 * Thrown by {@link AgentJwtVerifier} on verification failure. The pre-built {@link Response} is
 * what the calling endpoint returns to the client; {@link #errorCode()} and {@link #status()} are
 * kept available so call sites can branch on the failure mode without parsing the response entity.
 */
final class AgentJwtException extends Exception {

  private static final long serialVersionUID = 1L;

  private final transient Response response;
  private final String errorCode;
  private final int status;

  AgentJwtException(Response response, String errorCode, int status) {
    super(errorCode);
    this.response = response;
    this.errorCode = errorCode;
    this.status = status;
  }

  Response response() {
    return response;
  }

  String errorCode() {
    return errorCode;
  }

  int status() {
    return status;
  }
}
