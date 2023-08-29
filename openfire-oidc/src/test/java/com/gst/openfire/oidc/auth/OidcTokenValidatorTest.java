package com.gst.openfire.oidc.auth;

import org.jivesoftware.util.JiveProperties;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.Key;

class OidcTokenValidatorTest {

    private OidcTokenValidator validator;

    @BeforeEach
    void setup() {
        validator = new OidcTokenValidator();
    }

    @Test
    @Disabled("This test have to use valid Token")
    void testAuthenticateToken() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjX3ROVDJSOVJOcV93d3c4UUVXSFFNWWJ6SjNQOUJYRkdqRmJBOVNMY0g4In0.eyJleHAiOjE2OTMyOTU5MDIsImlhdCI6MTY5MzI5NTYwMiwianRpIjoiYTg4MDNhY2YtZjE5NC00NTNhLWE5OTQtYTBmZGFiMjhjMzE0IiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmV6Z28udm46ODAxMC9yZWFsbXMvTUVFVF9NRSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OGVhZWQwNC0wMmVmLTRkNDEtYTU5NS1lM2NjYjM1MDNiYjYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNRUVUX01FIiwic2Vzc2lvbl9zdGF0ZSI6IjZkODRiZjc4LWZiYjAtNDY2Yi1hNTljLTczYTk5YzE5Yzk0YSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWVldF9tZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiI2ZDg0YmY3OC1mYmIwLTQ2NmItYTU5Yy03M2E5OWMxOWM5NGEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6IjI1ODg2ODY4Njg2OCJ9.GXVFGRHHwL9gKBxZb3o-1uxYf7wQKw_h7b2AbSxfTlot-Oe0pAL_clWzg0scY1Oxd-J72O6jUCAt4lkF7O6gZRmAnESci_3BV_hnCQ--C7q8mCja244uQyTBRpK-e5cZP4vJyfamXTX3E7X7UF-fPQzFCT_vV1CQEQkW4KssydOEHmu7Z5z80uswoIik1kxv-31-DXkVdbT6l6Hr30XpGqqtxZ6AyLCJGvYiWw3IZYOBDOpylashqs3RSgTBElWpex-Ay4OjVN8VMRo2x0H1WG3KLpAnkIX-jQtc13f9Y0LDNZoac0UWYPy8wUsg9aNVEeAwzvxHY5np1xwlk_CuzA";
        String url = validator.getIssuerFromToken(token);
        Assertions.assertEquals(url, "https://demo.ezgo.vn:8010/realms/MEET_ME");
        Key key = validator.getKeycloakPublicKey(url);
        Assertions.assertNotNull(key);

        JwtClaims data = validator.verifyClaims(token, key);
        Assertions.assertNotNull(data);
    }
}
