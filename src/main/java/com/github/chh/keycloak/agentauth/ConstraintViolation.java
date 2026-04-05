package com.github.chh.keycloak.agentauth;

import java.util.Map;

/**
 * Represents a single constraint violation when validating execution arguments against capability
 * grant constraints.
 *
 * @param field
 *          the top-level input field name that violated its constraint
 * @param constraint
 *          the constraint definition that was violated
 * @param actual
 *          the actual value supplied by the agent
 */
public record ConstraintViolation(String field, Map<String, Object> constraint, Object actual) {
}
