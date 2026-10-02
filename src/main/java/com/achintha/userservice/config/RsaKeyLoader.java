package com.achintha.userservice.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

/**
 * Reads the RS256 key pair from PEM text or from a resource location. Supports PKCS#8 private keys ("BEGIN PRIVATE
 * KEY", what {@code openssl genpkey} writes) and X.509 public keys ("BEGIN PUBLIC KEY").
 */
public final class RsaKeyLoader {

    private static final int MIN_KEY_BITS = 2048;

    private RsaKeyLoader() {
    }

    public static KeyPair load(JwtProperties.Signing signing, ResourceLoader resourceLoader) {
        try {
            RSAPrivateKey privateKey = parsePrivateKey(read(signing.privateKey(), resourceLoader));
            RSAPublicKey publicKey = parsePublicKey(read(signing.publicKey(), resourceLoader));
            if (publicKey.getModulus().bitLength() < MIN_KEY_BITS) {
                throw new IllegalStateException("The JWT signing key must be at least " + MIN_KEY_BITS + " bits");
            }
            if (privateKey instanceof RSAPrivateCrtKey crt && !crt.getModulus().equals(publicKey.getModulus())) {
                throw new IllegalStateException("security.jwt.signing.public-key does not match the private key");
            }
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
            // Never include the key material in the message
            throw new IllegalStateException("Could not read the JWT signing keys (security.jwt.signing.*): "
                    + e.getClass().getSimpleName(), e);
        }
    }

    private static String read(String valueOrLocation, ResourceLoader resourceLoader) throws IOException {
        String trimmed = valueOrLocation.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            return trimmed;
        }
        Resource resource = resourceLoader.getResource(trimmed);
        if (!resource.exists()) {
            throw new IOException("Key resource not found: " + trimmed);
        }
        try (InputStream in = resource.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    private static RSAPrivateKey parsePrivateKey(String pem) throws GeneralSecurityException {
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            throw new IllegalArgumentException("PKCS#1 key: convert with 'openssl pkcs8 -topk8 -nocrypt'");
        }
        byte[] der = decode(pem, "PRIVATE KEY");
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static RSAPublicKey parsePublicKey(String pem) throws GeneralSecurityException {
        byte[] der = decode(pem, "PUBLIC KEY");
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] decode(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start < 0 || stop < start) {
            throw new IllegalArgumentException("Expected a PEM block of type " + type);
        }
        String base64 = pem.substring(start + begin.length(), stop).replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    public record KeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

        @Override
        public String toString() {
            return "KeyPair[publicKey=RSA, privateKey=****]";
        }
    }
}
