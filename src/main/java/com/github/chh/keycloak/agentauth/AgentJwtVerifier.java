package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Centralized §4.5 + §4.3 + §4.6 Agent JWT verification. Mirrors {@link HostJwtVerifier} for the
 * agent path: the catalog endpoints {@code GET /capability/list} and
 * {@code GET /capability/describe} previously open-coded a partial check that verified only the
 * signature, leaving {@code aud}, timestamps, replay, agent status and host status unenforced. This
 * helper unifies the pipeline so any future Server-API endpoint that authenticates with an
 * agent+jwt sees the same fully-checked result.
 *
 * <p>
 * The helper performs:
 * <ul>
 * <li>{@code typ=agent+jwt} header check (§4.3)</li>
 * <li>{@code jti}, {@code iat}, {@code exp} presence + freshness with clock skew (§4.5)</li>
 * <li>{@code aud} match against the expected receiver (caller-supplied; for catalog calls this is
 * the issuer URL)</li>
 * <li>{@code iss} presence and binding to the agent's parent host. Inline-key hosts MUST match the
 * stored {@code host_id} exactly; JWKS-served hosts may rotate their key out-of-band, in which case
 * we accept any {@code iss} that hashes to a key currently published at the host's
 * {@code host_jwks_url}.</li>
 * <li>Agent lookup by {@code sub}; lifecycle clocks (§§2.3-2.5) are evaluated lazily before the
 * status check so a stale {@code active} row is demoted to {@code expired}/{@code revoked} and
 * persisted before authentication proceeds.</li>
 * <li>Agent status check — must be {@code active}.</li>
 * <li>Owning host lookup by stored {@code host_id} with §4.5 JWKS-rotation fallback; host must
 * exist and be {@code active}</li>
 * <li>Signature verification against the agent's stored {@code agent_public_key} (with
 * {@code agent_jwks_url} fallback)</li>
 * <li>Replay check via the caller-supplied {@code jti} predicate (§4.6)</li>
 * </ul>
 *
 * <p>
 * Failure mode: throw {@link AgentJwtException} with a populated {@link Response}. The caller
 * returns the response unchanged.
 */
final class AgentJwtVerifier {

  private static final long DEFAULT_CLOCK_SKEW_MS = 30_000L;

  private final AgentAuthStorage storage;
  private final JwksCache jwksCache;
  private final java.util.function.BiPredicate<SignedJWT, String> jtiReplayCheck;
  private final long clockSkewMs;

  AgentJwtVerifier(
      AgentAuthStorage storage,
      JwksCache jwksCache,
      java.util.function.BiPredicate<SignedJWT, String> jtiReplayCheck) {
    this(storage, jwksCache, jtiReplayCheck, DEFAULT_CLOCK_SKEW_MS);
  }

  AgentJwtVerifier(
      AgentAuthStorage storage,
      JwksCache jwksCache,
      java.util.function.BiPredicate<SignedJWT, String> jtiReplayCheck,
      long clockSkewMs) {
    this.storage = storage;
    this.jwksCache = jwksCache;
    this.jtiReplayCheck = jtiReplayCheck;
    this.clockSkewMs = clockSkewMs;
  }

  /**
   * Run the agent-JWT verification pipeline for a bearer token. Pre-signature checks (typ, claims
   * presence, audience, timestamps, iss presence) run before any storage lookup; the agent and host
   * status checks run before the signature so a known-bad principal short-circuits without
   * consuming crypto. The §4.6 jti replay check is last so a verified-but-replayed JWT still
   * surfaces the replay error rather than a generic invalid-signature failure.
   *
   * <p>
   * Order of checks (per §4.5): parse claims → require iss → resolve agent by sub → apply
   * {@link LifecycleClock} → check agent status → resolve host (with JWKS fallback for
   * rotation-capable hosts) → check host status → verify signature → check exp/iat (already
   * pre-validated) → check jti replay.
   *
   * @param authHeader
   *          the raw {@code Authorization} header value, may be null
   * @param expectedAudience
   *          the {@code aud} value the JWT must carry — for catalog endpoints this is the server's
   *          issuer URL (per §4.3 / §4.5: non-execution Server-API requests use {@code aud=iss})
   */
  Result verify(String authHeader, String expectedAudience) throws AgentJwtException {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      throw fail(401, "authentication_required", "Missing or invalid Authorization header");
    }

    String token = authHeader.substring(7);
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed JWT");
    }

    if (jwt.getHeader().getType() == null
        || !"agent+jwt".equals(jwt.getHeader().getType().getType())) {
      throw fail(401, "invalid_jwt", "JWT must be type agent+jwt");
    }

    JWTClaimsSet claims;
    try {
      claims = jwt.getJWTClaimsSet();
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed JWT");
    }

    String jti = claims.getJWTID();
    if (jti == null) {
      throw fail(401, "invalid_jwt", "Missing jti");
    }

    if (claims.getIssueTime() == null || claims.getExpirationTime() == null) {
      throw fail(401, "invalid_jwt", "Missing timestamps");
    }

    long now = System.currentTimeMillis();
    if (claims.getIssueTime().getTime() > now + clockSkewMs) {
      throw fail(401, "invalid_jwt", "JWT issued in the future");
    }
    if (now > claims.getExpirationTime().getTime()) {
      throw fail(401, "invalid_jwt", "Token expired");
    }

    List<String> aud = claims.getAudience();
    if (aud == null || !aud.contains(expectedAudience)) {
      throw fail(401, "invalid_jwt", "Invalid audience");
    }

    // §4.3: iss is the host identifier. We require its presence early so subsequent checks have
    // something to bind against; the actual iss-vs-stored-host-id comparison happens after the
    // agent (and therefore the parent host_id) is resolved.
    String iss = claims.getIssuer();
    if (iss == null || iss.isBlank()) {
      throw fail(401, "invalid_jwt", "Missing issuer");
    }

    String sub = claims.getSubject();
    if (sub == null || sub.isBlank()) {
      throw fail(401, "invalid_jwt", "Missing sub");
    }

    Map<String, Object> agentData = storage.getAgent(sub);
    if (agentData == null) {
      throw fail(401, "invalid_jwt", "Unknown agent");
    }

    // §§2.3-2.5: lazy lifecycle-clock evaluation. A token may arrive while the stored status still
    // says `active`; the centralised evaluator demotes the row to `expired` or `revoked` before we
    // honour it. Persist any transition so subsequent flows (status, execute, introspect) see the
    // new value — same pattern as getAgentStatus / agentExecute / introspect.
    String statusBeforeClock = (String) agentData.get("status");
    LifecycleClock.Result clockResult = LifecycleClock.applyExpiry(agentData);
    if (clockResult != LifecycleClock.Result.ACTIVE
        && !Objects.equals(statusBeforeClock, agentData.get("status"))) {
      agentData.put("updated_at", Instant.now().toString());
      storage.putAgent(sub, agentData);
    }

    String agentStatus = (String) agentData.get("status");
    if (!"active".equals(agentStatus)) {
      // §2.3 agent states: pending/expired/revoked/rejected/claimed are all non-grantable. The
      // catalog endpoints don't differentiate per-state error codes — any non-active agent fails
      // the same way as a missing one.
      throw fail(401, "invalid_jwt", "Agent is not active");
    }

    String hostId = (String) agentData.get("host_id");
    if (hostId == null || hostId.isBlank()) {
      throw fail(401, "invalid_jwt", "Agent is not bound to a host");
    }

    Map<String, Object> hostData = storage.getHost(hostId);
    if (hostData == null) {
      throw fail(401, "invalid_jwt", "Unknown host");
    }

    // §4.3 + §4.5 host fallback: the JWT iss MUST identify the agent's parent host. Inline-key
    // hosts have a fixed thumbprint identity — iss must equal the stored host_id exactly. JWKS-
    // served hosts may rotate keys out of band, so we additionally accept any iss that matches a
    // key currently published at the host's host_jwks_url (thumbprint-of-resolved-key == iss).
    if (!hostId.equals(iss)) {
      String hostJwksUrl = (String) hostData.get("host_jwks_url");
      if (hostJwksUrl == null || hostJwksUrl.isBlank()) {
        // Inline-key host fails closed: no JWKS to consult, no rebind path.
        throw fail(401, "invalid_jwt", "Issuer does not match host");
      }
      if (!issMatchesPublishedJwk(hostJwksUrl, iss)) {
        throw fail(401, "invalid_jwt", "Issuer does not match host");
      }
    }

    String hostStatus = (String) hostData.get("status");
    if (!"active".equals(hostStatus)) {
      // Pending host or revoked host invalidates every agent under it for catalog access. Per
      // §2.11 agents under a pending host stay pending themselves, so the agent-status check
      // above will usually catch this — the host-status guard is defense-in-depth for the
      // (non-spec, but possible) scenario where storage drifts.
      throw fail(401, "invalid_jwt", "Owning host is not active");
    }

    Map<String, Object> agentKeyMap = resolveAgentPublicKey(jwt, agentData);

    OctetKeyPair agentKey;
    try {
      agentKey = OctetKeyPair.parse(agentKeyMap);
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed agent_public_key");
    }
    if (!com.nimbusds.jose.jwk.Curve.Ed25519.equals(agentKey.getCurve())) {
      throw fail(401, "invalid_jwt", "agent_public_key must be Ed25519");
    }

    JWSVerifier verifier;
    try {
      verifier = new Ed25519Verifier(agentKey);
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Unable to construct verifier");
    }

    boolean signatureOk;
    try {
      signatureOk = jwt.verify(verifier);
    } catch (Exception e) {
      signatureOk = false;
    }
    if (!signatureOk) {
      throw fail(401, "invalid_jwt", "Invalid signature");
    }

    if (jtiReplayCheck.test(jwt, jti)) {
      throw fail(401, "jti_replay", "Replay detected");
    }

    return new Result(jwt, jti, sub, agentData, hostId, hostData);
  }

  /**
   * Returns true if the given host JWKS endpoint currently publishes a key whose JWK thumbprint
   * equals {@code expectedIss}. We iterate the cached JWKS keys (re-fetching via the cache's
   * miss-window if the kid we're looking for isn't present yet) rather than indexing by kid,
   * because the JWT issuer is the thumbprint, not the kid — different keys may use different kids.
   */
  private boolean issMatchesPublishedJwk(String hostJwksUrl, String expectedIss) {
    Map<String, Map<String, Object>> keysByKid;
    try {
      keysByKid = jwksCache.resolveAll(hostJwksUrl);
    } catch (IllegalArgumentException e) {
      return false;
    }
    for (Map<String, Object> jwk : keysByKid.values()) {
      try {
        OctetKeyPair okp = OctetKeyPair.parse(jwk);
        if (expectedIss.equals(okp.computeThumbprint().toString())) {
          return true;
        }
      } catch (Exception ignored) {
        // skip malformed or non-OKP entries
      }
    }
    return false;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> resolveAgentPublicKey(SignedJWT jwt, Map<String, Object> agentData)
      throws AgentJwtException {
    String agentJwksUrl = (String) agentData.get("agent_jwks_url");
    if (agentJwksUrl != null && !agentJwksUrl.isBlank()) {
      String kid = jwt.getHeader().getKeyID();
      if (kid == null || kid.isBlank()) {
        kid = (String) agentData.get("agent_kid");
      }
      if (kid == null || kid.isBlank()) {
        throw fail(401, "invalid_jwt", "Missing kid for agent_jwks_url");
      }
      try {
        return jwksCache.resolve(agentJwksUrl, kid);
      } catch (IllegalArgumentException e) {
        throw fail(401, "invalid_jwt", e.getMessage() == null
            ? "Unable to resolve agent JWKS key"
            : e.getMessage());
      }
    }
    Map<String, Object> stored = (Map<String, Object>) agentData.get("agent_public_key");
    if (stored == null) {
      throw fail(401, "invalid_jwt", "Missing agent_public_key");
    }
    return stored;
  }

  private static AgentJwtException fail(int status, String error, String message) {
    Response response = Response.status(status)
        .entity(Map.of("error", error, "message", message))
        .build();
    return new AgentJwtException(response, error, status);
  }

  /** Outcome of a successful agent-JWT verification. */
  static final class Result {

    private final SignedJWT jwt;
    private final String jti;
    private final String agentId;
    private final Map<String, Object> agentData;
    private final String hostId;
    private final Map<String, Object> hostData;

    Result(SignedJWT jwt, String jti, String agentId, Map<String, Object> agentData,
        String hostId, Map<String, Object> hostData) {
      this.jwt = jwt;
      this.jti = jti;
      this.agentId = agentId;
      this.agentData = agentData;
      this.hostId = hostId;
      this.hostData = hostData;
    }

    SignedJWT jwt() {
      return jwt;
    }

    String jti() {
      return jti;
    }

    String agentId() {
      return agentId;
    }

    Map<String, Object> agentData() {
      return agentData;
    }

    String hostId() {
      return hostId;
    }

    Map<String, Object> hostData() {
      return hostData;
    }
  }
}
