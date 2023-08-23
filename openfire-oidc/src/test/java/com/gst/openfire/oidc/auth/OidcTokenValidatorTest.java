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
        validator = new OidcTokenValidator(JiveProperties.getInstance());
    }

    @Test
    @Disabled("This test have to use valid Token")
    void testAuthenticateToken() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjX3ROVDJSOVJOcV93d3c4UUVXSFFNWWJ6SjNQOUJYRkdqRmJBOVNMY0g4In0.eyJleHAiOjE2OTI2OTE3MDUsImlhdCI6MTY5MjY5MTQwNSwianRpIjoiMDVkMDAxODgtOWM0Mi00ZDRhLThmZmMtOWQ1NzBmOTE1M2FlIiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmV6Z28udm46ODAxMC9yZWFsbXMvTUVFVF9NRSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OGVhZWQwNC0wMmVmLTRkNDEtYTU5NS1lM2NjYjM1MDNiYjYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNRUVUX01FIiwic2Vzc2lvbl9zdGF0ZSI6IjFkMTZkOTUzLWY5MDUtNDVkZS1hMTliLWMwNjY1MjZkMGZkZSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWVldF9tZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiIxZDE2ZDk1My1mOTA1LTQ1ZGUtYTE5Yi1jMDY2NTI2ZDBmZGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6IjI1ODg2ODY4Njg2OCJ9.ypaURQi2sSQ-ArXRVwV5OxqMqhd8_FYPGE9aB4sNSnC837JJysiFz2OPsCZHEVINEdZOnFywS2IaZz58mhmk2ZdoggmddiYdk4dz7hswLdFWzvoApNMph9WVGfr9jM78YtHLB6p2sw5NNvL5R060ZjCgXCbfPShVa0gvDjTApSwPvbiYbHxHjuPrz9hj0z7rYnOZSPzHed6PwUzEt9xdCPrQ_VVGlcoiN3b9EJ3rBFrPatyBdXv2W_6km15XIU4AD4ERI91h3bi4W8ZS4-o9tnJDYDALOqku8_pjsPJKh1JXWbAcH28aQviTz4lf1wXbkGQDBiIrtfnHIiMPm4FC6Q";
        String url = validator.getIssuerFromToken(token);
        Assertions.assertEquals(url, "https://demo.ezgo.vn:8010/realms/MEET_ME");
        Key key = validator.getKeycloakPublicKey(url);
        Assertions.assertNotNull(key);

        JwtClaims data = validator.verifyClaims(token, key);
        Assertions.assertNotNull(data);
    }

    @Test
    @Disabled("This test have to config valid server property")
    void testGetAuthServerFromConfiguration() {
        String actualResult = validator.getAuthServerFromConfiguration();

        Assertions.assertEquals(actualResult, "https://demo.ezgo.vn:8010/realms/MEET_ME");
    }
}
