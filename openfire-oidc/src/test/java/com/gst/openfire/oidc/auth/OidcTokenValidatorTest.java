package com.gst.openfire.oidc.auth;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

class OidcTokenValidatorTest {

    private OidcTokenValidator validator;

    @BeforeEach
    void setup() throws JoseException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        OidcTokenValidator.authServerUrl = "https://demo.ezgo.vn:8010/realms/TEST";
        validator = new OidcTokenValidator();
    }

    @Test
    @Disabled("This test have to use valid Token")
    void testAuthenticateToken() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjX3ROVDJSOVJOcV93d3c4UUVXSFFNWWJ6SjNQOUJYRkdqRmJBOVNMY0g4In0.eyJleHAiOjE2OTM5MDkwOTAsImlhdCI6MTY5MzkwODc5MCwianRpIjoiNGMxM2E4NDYtMDM0Mi00ZDAzLTllZjItNWNmZTA0NjQ1ODRhIiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmV6Z28udm46ODAxMC9yZWFsbXMvTUVFVF9NRSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OGVhZWQwNC0wMmVmLTRkNDEtYTU5NS1lM2NjYjM1MDNiYjYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNRUVUX01FIiwic2Vzc2lvbl9zdGF0ZSI6Ijg1MjQ0OWVhLTg3NzctNDRlOS05NzdlLWJkMjU3MDE2YzdjYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWVldF9tZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiI4NTI0NDllYS04Nzc3LTQ0ZTktOTc3ZS1iZDI1NzAxNmM3Y2IiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6IjI1ODg2ODY4Njg2OCJ9.Bq1xZ2y4a7khKNvi0FN0x1y8EXNbyXt-Zgr4U-bAYuzDIB9nSRJAoI7rhmj0jmMdGcp-f5KXhfiLAvQ58Re6JG1sP-R57yNhcNlsMmmFAtk9777flj5DoEvSKJcRcdxtfp3_7iCSAVs82hsbv97YBvZOCQOqJpwtcZQSWQE67M8jwV3Am-psPxp0XNF3_GFYX3FCcl1a6xWHzpj_jRx-hmlQym7xm8yRN7-7JN-xzEa3D-pZGLgaR8Wab0t7TuaFpLCbjCQ8jq6c5-eLfyBiNgB54vEUezJn8Ad9OkX30d60fIhyai2IYXndLPC_jQ-_yqdHYCIjqBF8xJ0MQjD3Gg";

        JwtClaims data = validator.verifyClaims(token);

        Assertions.assertNotNull(data);
    }
}
