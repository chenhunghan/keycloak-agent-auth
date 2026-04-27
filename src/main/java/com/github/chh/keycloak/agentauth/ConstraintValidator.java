package com.github.chh.keycloak.agentauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Validates execution arguments against capability grant constraints per the Agent Auth Protocol
 * spec §2.13.
 *
 * <p>
 * Supported operators: {@code max}, {@code min}, {@code in}, {@code not_in}, and exact-value
 * literals for any JSON type (string, number, boolean, null, array, object).
 */
public class ConstraintValidator {

  private final ObjectMapper objectMapper = new ObjectMapper();

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
      } else if (!jsonEquals(constraintDef, actualValue)) {
        Map<String, Object> exactConstraint = new HashMap<>();
        exactConstraint.put("exact", constraintDef);
        violations.add(new ConstraintViolation(field, exactConstraint, actualValue));
      }
    }
    return violations;
  }

  private boolean jsonEquals(Object a, Object b) {
    return jsonNodeEquals(objectMapper.valueToTree(a), objectMapper.valueToTree(b));
  }

  // Recursive structural equality that treats numeric nodes by value (so 500 == 500.0), matching
  // JSON-level semantics rather than Java type identity. Jackson's JsonNode#equals is type-strict
  // for numbers, which would falsely reject equivalent integer/double pairs.
  private boolean jsonNodeEquals(JsonNode a, JsonNode b) {
    if (a == null || b == null) {
      return a == b;
    }
    if (a.isNumber() && b.isNumber()) {
      return a.decimalValue().compareTo(b.decimalValue()) == 0;
    }
    if (a.isArray() && b.isArray()) {
      if (a.size() != b.size()) {
        return false;
      }
      for (int i = 0; i < a.size(); i++) {
        if (!jsonNodeEquals(a.get(i), b.get(i))) {
          return false;
        }
      }
      return true;
    }
    if (a.isObject() && b.isObject()) {
      if (a.size() != b.size()) {
        return false;
      }
      Iterator<String> fields = a.fieldNames();
      while (fields.hasNext()) {
        String f = fields.next();
        if (!b.has(f) || !jsonNodeEquals(a.get(f), b.get(f))) {
          return false;
        }
      }
      return true;
    }
    return a.equals(b);
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
      if ("max".equals(operator)) {
        violated = !(actualValue instanceof Number) || !(opValue instanceof Number)
            || ((Number) actualValue).doubleValue() > ((Number) opValue).doubleValue();
      } else if ("min".equals(operator)) {
        violated = !(actualValue instanceof Number) || !(opValue instanceof Number)
            || ((Number) actualValue).doubleValue() < ((Number) opValue).doubleValue();
      } else if ("in".equals(operator)) {
        violated = !(opValue instanceof List) || actualValue == null
            || !((List<?>) opValue).contains(actualValue);
      } else if ("not_in".equals(operator)) {
        violated = !(opValue instanceof List)
            || (actualValue != null && ((List<?>) opValue).contains(actualValue));
      }
      if (violated) {
        violations.add(new ConstraintViolation(field, ops, actualValue));
        return;
      }
    }
  }
}
