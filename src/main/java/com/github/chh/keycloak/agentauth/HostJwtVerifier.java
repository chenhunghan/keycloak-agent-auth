package com.github.chh.keycloak.agentauth;

import com.github.chh.keycloak.agentauth.storage.AgentAuthStorage;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;

/**
 * Centralized §4.5.1 Host JWT verification. The legacy implementation copied this same logic into
 * each lifecycle endpoint inline-only — this helper unifies the path so all six endpoints share a
 * single implementation that supports both inline {@code host_public_key} and {@code host_jwks_url}
 * (§4.2) hosts.
 *
 * <p>
 * The helper intentionally stops at signature + replay checks. Per-endpoint policy (status checks,
 * §5.9 rotated-key guards) lives at the call site so each endpoint can pick the response codes it
 * needs.
 *
 * <p>
 * Failure mode: throw {@link HostJwtException} with a populated {@link Response}. The caller
 * returns the response unchanged.
 */
final class HostJwtVerifier {

  private static final long DEFAULT_CLOCK_SKEW_MS = 30_000L;

  private final AgentAuthStorage storage;
  private final JwksCache jwksCache;
  private final java.util.function.BiPredicate<SignedJWT, String> jtiReplayCheck;
  private final long clockSkewMs;

  HostJwtVerifier(
      AgentAuthStorage storage,
      JwksCache jwksCache,
      java.util.function.BiPredicate<SignedJWT, String> jtiReplayCheck) {
    this(storage, jwksCache, jtiReplayCheck, DEFAULT_CLOCK_SKEW_MS);
  }

  HostJwtVerifier(
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
   * Run the §4.5.1 verification pipeline for a bearer token. Pre-signature checks (typ, claims
   * presence, audience, timestamps) run before any storage lookup; signature verification runs
   * after host resolution; the §4.4 jti replay check runs last so that endpoints which skip the
   * replay step entirely (none today, but future endpoints might) can re-use the helper without
   * burning the jti.
   *
   * @param authHeader
   *          the raw {@code Authorization} header value, may be null
   * @param expectedAudience
   *          the {@code aud} value the JWT must carry
   * @param options
   *          per-endpoint behavior toggles
   */
  Result verify(String authHeader, String expectedAudience, Options options)
      throws HostJwtException {
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
        || !"host+jwt".equals(jwt.getHeader().getType().getType())) {
      throw fail(401, "invalid_jwt", "JWT must be type host+jwt");
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

    String iss = claims.getIssuer();
    if (iss == null || iss.isBlank()) {
      throw fail(401, "invalid_jwt", "Missing iss");
    }

    Map<String, Object> hostData = storage.getHost(iss);
    String hostJwksUrlClaim;
    try {
      hostJwksUrlClaim = claims.getStringClaim("host_jwks_url");
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed host_jwks_url claim");
    }

    boolean stored = hostData != null;
    boolean foundByJwksFallback = false;

    // §4.5.1 fallback: when the host record is unknown by `iss` but the JWT carries a
    // host_jwks_url, look the host up by its stable JWKS URL. The fallback lets a JWKS-served host
    // continue to authenticate after a key rotation flips its `iss` (thumbprint).
    if (!stored && hostJwksUrlClaim != null && !hostJwksUrlClaim.isBlank()) {
      Map<String, Object> byJwks = storage.findHostByJwksUrl(hostJwksUrlClaim);
      if (byJwks != null) {
        hostData = byJwks;
        stored = true;
        foundByJwksFallback = true;
      }
    }

    Map<String, Object> resolvedHostKeyJwk = resolveHostPublicKey(jwt, claims, hostData,
        hostJwksUrlClaim);

    OctetKeyPair hostKey;
    try {
      hostKey = OctetKeyPair.parse(resolvedHostKeyJwk);
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed host_public_key");
    }

    if (!com.nimbusds.jose.jwk.Curve.Ed25519.equals(hostKey.getCurve())) {
      throw fail(401, "invalid_jwt", "host_public_key must be Ed25519");
    }

    JWSVerifier verifier;
    try {
      verifier = new Ed25519Verifier(hostKey);
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

    String thumbprint;
    try {
      thumbprint = hostKey.computeThumbprint().toString();
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Unable to compute key thumbprint");
    }

    // §4.2: when the host carries an inline `host_public_key` claim, the JWK MUST hash to `iss`
    // (legacy thumbprint identity). When the host registered with `host_jwks_url`, the iss is the
    // stored thumbprint at registration time; the freshly fetched JWK doesn't have to match `iss`
    // because the JWKS endpoint is the source of truth and the host may have rotated keys
    // out-of-band.
    boolean hadInlineKey;
    try {
      hadInlineKey = claims.getJSONObjectClaim("host_public_key") != null;
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed host_public_key claim");
    }
    if (hadInlineKey && !thumbprint.equals(iss)) {
      throw fail(401, "invalid_jwt", "Issuer does not match host thumbprint");
    }

    if (!options.deferJtiCheck() && jtiReplayCheck.test(jwt, jti)) {
      throw fail(401, "jti_replay", "Replay detected");
    }

    boolean issRebindEligible = foundByJwksFallback && options.allowJwksUrlIssRebind();
    return new Result(jwt, jti, iss, hostData, stored, foundByJwksFallback, issRebindEligible,
        hostJwksUrlClaim);
  }

  /**
   * Run the deferred §4.4 jti replay check. Used by endpoints that opted into
   * {@link Options.Builder#deferJtiCheck(boolean)} so they can interleave host-status checks before
   * consuming the JTI.
   */
  void enforceJtiReplay(Result result) throws HostJwtException {
    if (jtiReplayCheck.test(result.jwt(), result.jti())) {
      throw fail(401, "jti_replay", "Replay detected");
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> resolveHostPublicKey(
      SignedJWT jwt, JWTClaimsSet claims, Map<String, Object> hostData, String hostJwksUrlClaim)
      throws HostJwtException {
    Map<String, Object> inline;
    try {
      inline = claims.getJSONObjectClaim("host_public_key");
    } catch (Exception e) {
      throw fail(401, "invalid_jwt", "Malformed host_public_key claim");
    }
    if (inline != null) {
      return inline;
    }

    // Prefer the stored host_jwks_url (canonical, set at registration) over the JWT's claim.
    // Falling back to the claim covers the unknown-host registration path, but the lifecycle
    // helper is only called for known hosts so the stored URL is the load-bearing source.
    String jwksUrl = hostData == null ? null : (String) hostData.get("host_jwks_url");
    if (jwksUrl == null || jwksUrl.isBlank()) {
      jwksUrl = hostJwksUrlClaim;
    }
    if (jwksUrl == null || jwksUrl.isBlank()) {
      // No inline key, no JWKS URL, no stored host: the JWT is unverifiable.
      throw fail(401, "invalid_jwt", "Missing host_public_key");
    }

    String kid = jwt.getHeader().getKeyID();
    if ((kid == null || kid.isBlank()) && hostData != null) {
      kid = (String) hostData.get("host_kid");
    }
    if (kid == null || kid.isBlank()) {
      throw fail(401, "invalid_jwt", "Missing kid for host_jwks_url");
    }

    try {
      return jwksCache.resolve(jwksUrl, kid);
    } catch (IllegalArgumentException e) {
      throw fail(401, "invalid_jwt", e.getMessage() == null
          ? "Unable to resolve host JWKS key"
          : e.getMessage());
    }
  }

  private static HostJwtException fail(int status, String error, String message) {
    Response response = Response.status(status)
        .entity(Map.of("error", error, "message", message))
        .build();
    return new HostJwtException(response, error, status);
  }

  /** Per-endpoint options threaded through the verifier. */
  static final class Options {

    private final boolean allowJwksUrlIssRebind;
    private final boolean deferJtiCheck;

    private Options(boolean allowJwksUrlIssRebind, boolean deferJtiCheck) {
      this.allowJwksUrlIssRebind = allowJwksUrlIssRebind;
      this.deferJtiCheck = deferJtiCheck;
    }

    /** Default: do not rebind {@code iss} and consume jti during verification. */
    static Options defaults() {
      return new Options(false, false);
    }

    /**
     * §5.9 rotate-host-key: the JWT presents a new {@code iss} (post-rotation thumbprint), but the
     * stored host is found by {@code host_jwks_url} fallback. Allowed for the rotate-key path so
     * the storage row's PK can be migrated; rejected on every other endpoint.
     */
    static Options forRotateHostKey() {
      return new Options(true, false);
    }

    /**
     * Defer the §4.4 jti replay check to the caller, which must subsequently invoke
     * {@link HostJwtVerifier#enforceJtiReplay(Result)}. Used by {@code GET /agent/status} so a
     * revoked-host check can fire 403 before the (already-consumed) jti would 401.
     */
    static Options forAgentStatus() {
      return new Options(false, true);
    }

    boolean allowJwksUrlIssRebind() {
      return allowJwksUrlIssRebind;
    }

    boolean deferJtiCheck() {
      return deferJtiCheck;
    }
  }

  /** Outcome of a successful host-JWT verification. */
  static final class Result {

    private final SignedJWT jwt;
    private final String jti;
    private final String iss;
    private final Map<String, Object> hostData;
    private final boolean storedHost;
    private final boolean foundByJwksFallback;
    private final boolean issRebindEligible;
    private final String hostJwksUrlClaim;

    Result(
        SignedJWT jwt, String jti, String iss, Map<String, Object> hostData,
        boolean storedHost, boolean foundByJwksFallback, boolean issRebindEligible,
        String hostJwksUrlClaim) {
      this.jwt = jwt;
      this.jti = jti;
      this.iss = iss;
      this.hostData = hostData;
      this.storedHost = storedHost;
      this.foundByJwksFallback = foundByJwksFallback;
      this.issRebindEligible = issRebindEligible;
      this.hostJwksUrlClaim = hostJwksUrlClaim;
    }

    SignedJWT jwt() {
      return jwt;
    }

    String jti() {
      return jti;
    }

    String iss() {
      return iss;
    }

    /** Stored host record if the host is known to the server; {@code null} otherwise. */
    Map<String, Object> hostData() {
      return hostData;
    }

    /** True when {@link #hostData()} is non-null (host known to the server). */
    boolean storedHost() {
      return storedHost;
    }

    /**
     * True when the host was found via the §4.5.1 {@code host_jwks_url} fallback (initial lookup by
     * {@code iss} missed). Endpoints that mutate the host record can use this to decide whether to
     * migrate the storage row's PK from the stale thumbprint to the new {@code iss}.
     */
    boolean foundByJwksFallback() {
      return foundByJwksFallback;
    }

    /**
     * True when the host was located via {@code host_jwks_url} fallback AND the calling endpoint
     * opted in to {@code iss} rebind via {@link Options#allowJwksUrlIssRebind()}. Currently only
     * {@code POST /host/rotate-key} sets this; other endpoints always see {@code false}.
     */
    boolean issRebindEligible() {
      return issRebindEligible;
    }

    String hostJwksUrlClaim() {
      return hostJwksUrlClaim;
    }
  }
}
