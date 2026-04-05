package com.github.chh.keycloak.agentauth.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

/** Utility for generating Ed25519 key pairs used in Agent Auth Protocol tests. */
public final class TestKeys {

  private TestKeys() {
  }

  /** Generates a fresh Ed25519 key pair as a Nimbus OctetKeyPair (OKP). */
  public static OctetKeyPair generateEd25519() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
      java.security.KeyPair keyPair = generator.generateKeyPair();

      EdECPublicKey publicKey = (EdECPublicKey) keyPair.getPublic();
      EdECPrivateKey privateKey = (EdECPrivateKey) keyPair.getPrivate();

      byte[] x = encodePublicKey(publicKey);
      byte[] d = privateKey.getBytes()
          .orElseThrow(() -> new IllegalStateException("Missing Ed25519 private key bytes"));

      return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x))
          .d(Base64URL.encode(d))
          .build();
    } catch (Exception e) {
      throw new AssertionError("Failed to generate Ed25519 key pair", e);
    }
  }

  /** Returns the JWK thumbprint (SHA-256, base64url) used as the host issuer claim. */
  public static String thumbprint(OctetKeyPair key) {
    try {
      return key.computeThumbprint().toString();
    } catch (JOSEException e) {
      throw new AssertionError("Failed to compute JWK thumbprint", e);
    }
  }

  private static byte[] encodePublicKey(EdECPublicKey publicKey) {
    byte[] encoded = new byte[32];
    byte[] y = publicKey.getPoint().getY().toByteArray();

    int yLength = Math.min(32, y.length);
    for (int i = 0; i < yLength; i++) {
      encoded[i] = y[y.length - 1 - i];
    }

    if (publicKey.getPoint().isXOdd()) {
      encoded[31] |= (byte) 0x80;
    }

    return encoded;
  }
}
