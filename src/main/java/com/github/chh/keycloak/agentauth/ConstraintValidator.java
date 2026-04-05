package com.github.chh.keycloak.agentauth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates execution arguments against capability grant constraints per the Agent Auth Protocol
 * spec §2.13.
 *
 * <p>
 * Supported operators: {@code max}, {@code min}, {@code in}, {@code not_in}, and exact-value (plain
 * string).
 */
public class ConstraintValidator {

  /**
   * Validates the supplied arguments against the granted constraints.
   *
   * @param constraints
   *          the constraint definitions from the capability grant
   * @param arguments
   *          the execution arguments supplied by the agent
   * @return list of violations; empty if all constraints are satisfied
   */
  public List<ConstraintViolation> validate(
      Map<String, Object> constraints, Map<String, Object> arguments) {
    List<ConstraintViolation> violations = new ArrayList<>();
    if (constraints == null) {
      return violations;
    }
    Map<String, Object> args = arguments != null ? arguments : new HashMap<>();
    for (Map.Entry<String, Object> entry : constraints.entrySet()) {
      String field = entry.getKey();
      Object constraintDef = entry.getValue();
      Object actualValue = args.get(field);
      if (constraintDef instanceof Map) {
        @SuppressWarnings("unchecked")
        Map<String, Object> ops = (Map<String, Object>) constraintDef;
        checkOperators(field, ops, actualValue, violations);
      } else if (constraintDef instanceof String && !constraintDef.equals(actualValue)) {
        Map<String, Object> exactConstraint = new HashMap<>();
        exactConstraint.put("exact", constraintDef);
        violations.add(new ConstraintViolation(field, exactConstraint, actualValue));
      }
    }
    return violations;
  }

  private void checkOperators(String field, Map<String, Object> ops, Object actualValue,
      List<ConstraintViolation> violations) {
    for (Map.Entry<String, Object> opEntry : ops.entrySet()) {
      String operator = opEntry.getKey();
      Object opValue = opEntry.getValue();
      if (!"max".equals(operator) && !"min".equals(operator) && !"in".equals(operator)
          && !"not_in".equals(operator)) {
        throw new IllegalArgumentException("Unknown constraint operator: " + operator);
      }
      boolean violated = false;
      if ("max".equals(operator) && actualValue instanceof Number) {
        violated = ((Number) actualValue).doubleValue() > ((Number) opValue).doubleValue();
      } else if ("min".equals(operator) && actualValue instanceof Number) {
        violated = ((Number) actualValue).doubleValue() < ((Number) opValue).doubleValue();
      } else if ("in".equals(operator) && actualValue != null) {
        @SuppressWarnings("unchecked")
        List<Object> inList = (List<Object>) opValue;
        violated = !inList.contains(actualValue);
      } else if ("not_in".equals(operator) && actualValue != null) {
        @SuppressWarnings("unchecked")
        List<Object> notInList = (List<Object>) opValue;
        violated = notInList.contains(actualValue);
      }
      if (violated) {
        violations.add(new ConstraintViolation(field, ops, actualValue));
        return;
      }
    }
  }
}
