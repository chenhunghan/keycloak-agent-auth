package com.github.chh.keycloak.agentauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for capability constraint validation per the Agent Auth Protocol spec.
 *
 * <p>
 * Constraints restrict agent-supplied execution arguments. Supported constraint forms:
 *
 * <ul>
 * <li>Exact value: {@code "field": value} — agent must supply exactly this value
 * <li>Max: {@code "field": {"max": N}} — value must be ≤ N
 * <li>Min: {@code "field": {"min": N}} — value must be ≥ N
 * <li>In: {@code "field": {"in": [...]}} — value must be in the list
 * <li>Not_in: {@code "field": {"not_in": [...]}} — value must not be in the list
 * <li>Combined: {@code "field": {"min": 0, "max": 1000}} — all operators must be satisfied
 * </ul>
 *
 * <p>
 * These tests define the contract for a {@code ConstraintValidator} class that will validate
 * execution arguments against granted constraints. Tests will fail until the implementation exists.
 */
class ConstraintValidatorTest {

  private final ConstraintValidator validator = new ConstraintValidator();

  // --- Exact value constraints ---

  @Test
  void exactValueConstraintPassesWhenMatched() {
    Map<String, Object> constraints = Map.of("destination_account", "acc_456");
    Map<String, Object> arguments = Map.of("destination_account", "acc_456");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactValueConstraintFailsWhenDifferent() {
    Map<String, Object> constraints = Map.of("destination_account", "acc_456");
    Map<String, Object> arguments = Map.of("destination_account", "acc_789");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("destination_account");
  }

  // --- Max constraint ---

  @Test
  void maxConstraintPassesWhenUnder() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of("amount", 500);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void maxConstraintPassesWhenEqual() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of("amount", 1000);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void maxConstraintFailsWhenExceeded() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of("amount", 5000);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("amount");
    assertThat(violations.get(0).constraint()).containsEntry("max", 1000);
    assertThat(violations.get(0).actual()).isEqualTo(5000);
  }

  // --- Min constraint ---

  @Test
  void minConstraintPassesWhenAbove() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 10));
    Map<String, Object> arguments = Map.of("amount", 50);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void minConstraintPassesWhenEqual() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 10));
    Map<String, Object> arguments = Map.of("amount", 10);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void minConstraintFailsWhenBelow() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 10));
    Map<String, Object> arguments = Map.of("amount", 5);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("amount");
  }

  // --- In constraint ---

  @Test
  void inConstraintPassesWhenValueInList() {
    Map<String, Object> constraints = Map.of("currency", Map.of("in", List.of("USD", "EUR")));
    Map<String, Object> arguments = Map.of("currency", "USD");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void inConstraintFailsWhenValueNotInList() {
    Map<String, Object> constraints = Map.of("currency", Map.of("in", List.of("USD", "EUR")));
    Map<String, Object> arguments = Map.of("currency", "GBP");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("currency");
  }

  // --- Not_in constraint ---

  @Test
  void notInConstraintPassesWhenValueNotInList() {
    Map<String, Object> constraints = Map.of("country",
        Map.of("not_in", List.of("SANCTIONED_A", "SANCTIONED_B")));
    Map<String, Object> arguments = Map.of("country", "US");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void notInConstraintFailsWhenValueInList() {
    Map<String, Object> constraints = Map.of("country",
        Map.of("not_in", List.of("SANCTIONED_A", "SANCTIONED_B")));
    Map<String, Object> arguments = Map.of("country", "SANCTIONED_A");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("country");
  }

  // --- Combined constraints ---

  @Test
  void combinedMinMaxPassesWhenInRange() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 0, "max", 1000));
    Map<String, Object> arguments = Map.of("amount", 500);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void combinedMinMaxFailsWhenBelowMin() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 0, "max", 1000));
    Map<String, Object> arguments = Map.of("amount", -1);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
  }

  @Test
  void combinedMinMaxFailsWhenAboveMax() {
    Map<String, Object> constraints = Map.of("amount", Map.of("min", 0, "max", 1000));
    Map<String, Object> arguments = Map.of("amount", 1001);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
  }

  // --- Multiple field constraints ---

  @Test
  void multipleFieldConstraintsAllPass() {
    Map<String, Object> constraints = Map.of(
        "amount", Map.of("max", 1000),
        "currency", Map.of("in", List.of("USD", "EUR")),
        "destination_account", "acc_456");
    Map<String, Object> arguments = Map.of(
        "amount", 500,
        "currency", "USD",
        "destination_account", "acc_456");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void multipleFieldConstraintsReportsAllViolations() {
    Map<String, Object> constraints = Map.of(
        "amount", Map.of("max", 1000),
        "currency", Map.of("in", List.of("USD", "EUR")));
    Map<String, Object> arguments = Map.of(
        "amount", 5000,
        "currency", "GBP");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(2);
  }

  // --- Edge cases ---

  @Test
  void noConstraintsMeansNoViolations() {
    Map<String, Object> constraints = Map.of();
    Map<String, Object> arguments = Map.of("anything", "goes");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void missingArgumentForConstrainedFieldIsViolation() {
    Map<String, Object> constraints = Map.of("required_field", "expected_value");
    Map<String, Object> arguments = Map.of();

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("required_field");
  }

  @Test
  void missingArgumentForOperatorConstraintIsViolation() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of();

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);

    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("amount");
  }

  @Test
  void wrongTypeForNumericOperatorConstraintIsViolation() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of("amount", "high");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);

    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("amount");
  }

  @Test
  void extraArgumentsWithoutConstraintsAreAllowed() {
    Map<String, Object> constraints = Map.of("amount", Map.of("max", 1000));
    Map<String, Object> arguments = Map.of(
        "amount", 500,
        "note", "this field has no constraint");

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void unknownConstraintOperatorFailsFast() {
    Map<String, Object> constraints = Map.of("amount", Map.of("between", List.of(1, 10)));
    Map<String, Object> arguments = Map.of("amount", 5);

    assertThatThrownBy(() -> validator.validate(constraints, arguments))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("between");
  }

  // --- Exact-value constraints for non-string JSON types (spec §2.13) ---

  @Test
  void exactNumberConstraintPassesWhenMatched() {
    Map<String, Object> constraints = Map.of("amount", 500);
    Map<String, Object> arguments = Map.of("amount", 500);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactNumberConstraintFailsWhenDifferent() {
    Map<String, Object> constraints = Map.of("amount", 500);
    Map<String, Object> arguments = Map.of("amount", 501);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("amount");
    assertThat(violations.get(0).constraint()).containsEntry("exact", 500);
    assertThat(violations.get(0).actual()).isEqualTo(501);
  }

  @Test
  void exactNumberConstraintMatchesAcrossIntegerAndDouble() {
    Map<String, Object> constraints = Map.of("amount", 500);
    Map<String, Object> arguments = Map.of("amount", 500.0);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactBooleanConstraintPassesWhenMatched() {
    Map<String, Object> constraints = Map.of("approved", true);
    Map<String, Object> arguments = Map.of("approved", true);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactBooleanConstraintFailsWhenDifferent() {
    Map<String, Object> constraints = Map.of("approved", true);
    Map<String, Object> arguments = Map.of("approved", false);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("approved");
    assertThat(violations.get(0).constraint()).containsEntry("exact", true);
    assertThat(violations.get(0).actual()).isEqualTo(false);
  }

  @Test
  void exactArrayConstraintPassesWhenMatched() {
    Map<String, Object> constraints = Map.of("tags", List.of("a", "b"));
    Map<String, Object> arguments = Map.of("tags", List.of("a", "b"));

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactArrayConstraintFailsWhenDifferent() {
    Map<String, Object> constraints = Map.of("tags", List.of("a", "b"));
    Map<String, Object> arguments = Map.of("tags", List.of("a", "c"));

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("tags");
  }

  // A top-level Map-valued constraint is interpreted as operator dispatch (see
  // unknownConstraintOperatorFailsFast). Nested-object exact equality is therefore covered via an
  // array of objects, which exercises the same JSON-equality path.
  @Test
  void exactObjectConstraintPassesWhenMatched() {
    Map<String, Object> constraints = Map.of("rules", List.of(Map.of("k", "v"), Map.of("n", 1)));
    Map<String, Object> arguments = Map.of("rules", List.of(Map.of("k", "v"), Map.of("n", 1)));

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactObjectConstraintFailsWhenDifferent() {
    Map<String, Object> constraints = Map.of("rules", List.of(Map.of("k", "v")));
    Map<String, Object> arguments = Map.of("rules", List.of(Map.of("k", "different")));

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("rules");
  }

  @Test
  void exactNullConstraintPassesWhenActualIsNull() {
    Map<String, Object> constraints = new HashMap<>();
    constraints.put("x", null);
    Map<String, Object> arguments = new HashMap<>();
    arguments.put("x", null);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactNullConstraintPassesWhenFieldOmitted() {
    Map<String, Object> constraints = new HashMap<>();
    constraints.put("x", null);
    Map<String, Object> arguments = Map.of();

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).isEmpty();
  }

  @Test
  void exactNullConstraintFailsWhenActualIsNonNull() {
    Map<String, Object> constraints = new HashMap<>();
    constraints.put("x", null);
    Map<String, Object> arguments = Map.of("x", 0);

    List<ConstraintViolation> violations = validator.validate(constraints, arguments);
    assertThat(violations).hasSize(1);
    assertThat(violations.get(0).field()).isEqualTo("x");
    assertThat(violations.get(0).actual()).isEqualTo(0);
  }
}
