package com.gst.openfire.oidc.auth;

import org.jivesoftware.util.JiveProperties;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

public class OidcTokenValidator {

    private static Logger logger = LoggerFactory.getLogger(OidcTokenValidator.class);
    private JiveProperties jiveProperties;

    public OidcTokenValidator(JiveProperties jiveProperties) {
        logger.info("Init keycloak token validator");
        this.jiveProperties = jiveProperties;
    }

    public OidcTokenValidator() {
    }

    public JwtClaims verifyToken(String token) throws InvalidJwtException,
        NoSuchAlgorithmException, InvalidKeySpecException, JoseException, IOException {
        String url = getAuthServerFromConfiguration();
        if (url == null) {
            throw new IllegalStateException("no auth server found in configuration");
        }
        Key key = getKeycloakPublicKey(url);
        return verifyClaims(token, key);
    }

    private String getAuthServerFromConfiguration() {
        return jiveProperties.getProperty("authServer",
            "https://gsttech.vddns.vn:8010/realms/CungLamTest");
    }

    String getIssuerFromToken(String token) throws MalformedClaimException, InvalidJwtException {
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature()
            .setSkipSignatureVerification().build();
        JwtContext jwtContext = firstPassJwtConsumer.process(token);
        return jwtContext.getJwtClaims().getIssuer();
    }

    PublicKey getKeycloakPublicKey(String realmURL)
        throws JoseException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        URLConnection conn = new URL(realmURL).openConnection();
        try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String realmInfo = reader.lines().collect(Collectors.joining("\n"));
            Map<String, Object> json = JsonUtil.parseJson(realmInfo);
            String publicKey = (String) json.get("public_key");

            byte[] publicBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        }

    }

    public JwtClaims verifyClaims(String token, Key key) throws InvalidJwtException {
        AlgorithmConstraints algorithmConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
            AlgorithmIdentifiers.RSA_USING_SHA256, AlgorithmIdentifiers.RSA_USING_SHA384);
        JwtConsumer secondPassJwtConsumer = new JwtConsumerBuilder()
            // .setExpectedIssuer(issuer)
            .setVerificationKey(key).setRequireExpirationTime().setAllowedClockSkewInSeconds(30).setRequireSubject()
            .setExpectedAudience(getAudienceFromConfiguration())
            .setJwsAlgorithmConstraints(algorithmConstraints).build();
        JwtClaims claims = secondPassJwtConsumer.processToClaims(token);
        logger.debug("verified claims: {}", claims);
        return claims;
    }

    private String getAudienceFromConfiguration() {
        return jiveProperties.getProperty("audience", "defaultAudience");
    }
}
