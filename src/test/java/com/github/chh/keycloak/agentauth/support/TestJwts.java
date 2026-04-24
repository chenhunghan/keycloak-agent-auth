package com.github.chh.keycloak.agentauth.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Builder utilities for creating host+jwt and agent+jwt tokens per the Agent Auth Protocol spec.
 *
 * <p>
 * All JWTs are signed with Ed25519 (EdDSA) as required by the protocol.
 */
public final class TestJwts {

  private TestJwts() {
  }

  /**
   * Builds a host+jwt for agent registration.
   *
   * @param hostKey
   *          the host's Ed25519 key pair (signs the JWT, public key becomes host identity)
   * @param agentKey
   *          the agent's Ed25519 key pair (public key embedded for server to store)
   * @param audience
   *          the server's issuer URL (aud claim)
   */
  public static String hostJwtForRegistration(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String audience) {
    return hostJwtForRegistration(hostKey, agentKey, audience, Map.of());
  }

  /**
   * Builds a host+jwt for agent registration with additional claims.
   *
   * @param hostKey
   *          the host's Ed25519 key pair
   * @param agentKey
   *          the agent's Ed25519 key pair
   * @param audience
   *          the server's issuer URL
   * @param extraClaims
   *          additional claims to include in the JWT
   */
  public static String hostJwtForRegistration(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String audience,
      Map<String, Object> extraClaims) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("host+jwt"))
          .build();

      long now = System.currentTimeMillis();
      JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject());

      extraClaims.forEach(claims::claim);

      SignedJWT jwt = new SignedJWT(header, claims.build());
      jwt.sign(new Ed25519Signer(hostKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create host JWT for registration", e);
    }
  }

  /** Builds a registration host+jwt that references the agent key through agent_jwks_url. */
  public static String hostJwtForRegistrationWithAgentJwksUrl(
      OctetKeyPair hostKey, String agentJwksUrl, String agentKid, String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("host+jwt"))
          .build();

      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .claim("agent_jwks_url", agentJwksUrl)
          .claim("agent_kid", agentKid)
          .build();

      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(hostKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create host JWT for agent JWKS registration", e);
    }
  }

  /** Builds a registration host+jwt that references the host signing key through host_jwks_url. */
  public static String hostJwtForRegistrationWithHostJwksUrl(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String hostJwksUrl, String hostKid,
      String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("host+jwt"))
          .keyID(hostKid)
          .build();

      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_jwks_url", hostJwksUrl)
          .claim("agent_public_key", agentKey.toPublicJWK().toJSONObject())
          .build();

      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(hostKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create host JWT for host JWKS registration", e);
    }
  }

  /**
   * Builds a host+jwt for non-registration operations (status, revoke, reactivate, key rotation).
   *
   * @param hostKey
   *          the host's Ed25519 key pair
   * @param audience
   *          the server's issuer URL
   */
  public static String hostJwt(OctetKeyPair hostKey, String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("host+jwt"))
          .build();

      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .build();

      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(hostKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create host JWT", e);
    }
  }

  /**
   * Builds an agent+jwt for capability execution or authenticated requests.
   *
   * @param hostKey
   *          the host's Ed25519 key pair (iss = host thumbprint)
   * @param agentKey
   *          the agent's Ed25519 key pair (signs the JWT)
   * @param agentId
   *          the agent's server-assigned ID (sub claim)
   * @param audience
   *          the target URL (aud claim — capability location or server issuer)
   */
  public static String agentJwt(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String audience) {
    return agentJwt(hostKey, agentKey, agentId, audience, Map.of());
  }

  /**
   * Builds an agent+jwt with additional claims.
   *
   * @param hostKey
   *          the host's Ed25519 key pair (iss = host thumbprint)
   * @param agentKey
   *          the agent's Ed25519 key pair (signs the JWT)
   * @param agentId
   *          the agent's server-assigned ID (sub claim)
   * @param audience
   *          the target URL (aud claim — capability location or server issuer)
   * @param extraClaims
   *          additional claims to include in the JWT
   */
  public static String agentJwt(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String audience,
      Map<String, Object> extraClaims) {
    return agentJwt(hostKey, agentKey, agentId, audience, extraClaims, null);
  }

  /** Builds an agent+jwt with a JOSE {@code kid} header. */
  public static String agentJwtWithKid(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String audience,
      String kid) {
    return agentJwt(hostKey, agentKey, agentId, audience, Map.of(), kid);
  }

  private static String agentJwt(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String audience,
      Map<String, Object> extraClaims, String kid) {
    try {
      JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"));
      if (kid != null && !kid.isBlank()) {
        headerBuilder.keyID(kid);
      }
      JWSHeader header = headerBuilder.build();

      long now = System.currentTimeMillis();
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .subject(agentId)
          .audience(audience)
          .issueTime(new Date(now))
          .expirationTime(new Date(now + 60_000))
          .jwtID("a-" + UUID.randomUUID())
          .build();

      JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder(claims);
      extraClaims.forEach(claimsBuilder::claim);

      SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
      jwt.sign(new Ed25519Signer(agentKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create agent JWT", e);
    }
  }

  /**
   * Builds an expired host+jwt for testing expiration rejection.
   *
   * @param hostKey
   *          the host's Ed25519 key pair
   * @param audience
   *          the server's issuer URL
   */
  public static String expiredHostJwt(OctetKeyPair hostKey, String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("host+jwt"))
          .build();

      long pastTime = System.currentTimeMillis() - 120_000;
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .audience(audience)
          .issueTime(new Date(pastTime))
          .expirationTime(new Date(pastTime + 60_000))
          .jwtID("h-" + UUID.randomUUID())
          .claim("host_public_key", hostKey.toPublicJWK().toJSONObject())
          .build();

      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(hostKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create expired host JWT", e);
    }
  }

  /**
   * Builds an expired agent+jwt for testing expiration rejection.
   *
   * @param hostKey
   *          the host's Ed25519 key pair
   * @param agentKey
   *          the agent's Ed25519 key pair
   * @param agentId
   *          the agent's server-assigned ID
   * @param audience
   *          the target URL
   */
  public static String expiredAgentJwt(
      OctetKeyPair hostKey, OctetKeyPair agentKey, String agentId, String audience) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
          .type(new JOSEObjectType("agent+jwt"))
          .build();

      long pastTime = System.currentTimeMillis() - 120_000;
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .issuer(TestKeys.thumbprint(hostKey))
          .subject(agentId)
          .audience(audience)
          .issueTime(new Date(pastTime))
          .expirationTime(new Date(pastTime + 60_000))
          .jwtID("a-" + UUID.randomUUID())
          .build();

      SignedJWT jwt = new SignedJWT(header, claims);
      jwt.sign(new Ed25519Signer(agentKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to create expired agent JWT", e);
    }
  }
}
