package com.gst.example.smack;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.sasl.SASLErrorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;

@Disabled("This test actually connected to the server")
class SmackExampleTest {

    private SmackExample smackExample;

    @BeforeEach
    void setup() {
        smackExample = new SmackExample();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"ValidOpenFireUser_ShouldSuccess, admin, An2404",
            "validKeycloakUser_ShouldSuccess, 258868686868, eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjX3ROVDJSOVJOcV93d3c4UUVXSFFNWWJ6SjNQOUJYRkdqRmJBOVNMY0g4In0.eyJleHAiOjE2OTI2OTkwMzIsImlhdCI6MTY5MjY5ODczMiwianRpIjoiYTg4YmJmNTYtMDVhNi00MjdkLTg3N2UtOTFlMjllODZiM2Y0IiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmV6Z28udm46ODAxMC9yZWFsbXMvTUVFVF9NRSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OGVhZWQwNC0wMmVmLTRkNDEtYTU5NS1lM2NjYjM1MDNiYjYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNRUVUX01FIiwic2Vzc2lvbl9zdGF0ZSI6Ijk4YWY2MmMyLWYxMDktNDJiMS04ODE4LWYzNGVjMGM4MWYyMyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWVldF9tZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiI5OGFmNjJjMi1mMTA5LTQyYjEtODgxOC1mMzRlYzBjODFmMjMiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6IjI1ODg2ODY4Njg2OCJ9.wUSl6ioMgyu5QtZCcb_89xWvt6jzTYjtGqrWpXE0wutcPUVwLMUUifLvF4aAZwQR9544CbPl4ZOHdlUDeDjeiXyzRcEX03EjzEnoKVq4xzDpBKm9vZeXjMagn3FcNWpzMmkLRy5o_Nnl-F3zSPRqP-YkM9i-07QbeObtkEbXEhv20EYGg4U4DTWpZD4fPNnG0-3YuPPk94fufxrhJVQRQ8lzrYaMi4ipHSRQK-sEzGrAHb-cC01CxuhfYn18gDiuHaCBVp0O84rCNugp7eojMi5zPBtJ7a-C8v-SsONA7mDOYn1e3ileTWq-MptZxCoWQuKXzbUucxdhwSJUv5DtzA"
    })
    void testLogin_ValidOpenFireUser_ShouldSuccess(String testName, String username, String password) throws InterruptedException, XMPPException, SmackException, IOException {
        AbstractXMPPConnection connection = smackExample.createConnection(username, password);

        Assertions.assertTrue(connection.isConnected());

        connection.disconnect();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"DefaultKeycloakPlainPassword_ShouldFailed, technician01, keycloakuser",
            "InvalidOpenFirePassword_ShouldFailed, cunglam, 1234",
            "InvalidKeycloakPassword_ShouldFailed, technician01, invalidToken",
            "NotExistedUser_ShouldFailed, notexisted, 123",})
    void testLogin_InvalidOpenFireUser_ShouldThrowNotAuthorizedException(String testName, String username, String password) {
        Assertions.assertThrowsExactly(SASLErrorException.class,
                () -> smackExample.createConnection(username, password),
                "SASLError using PLAIN: not-authorized");
    }

}
