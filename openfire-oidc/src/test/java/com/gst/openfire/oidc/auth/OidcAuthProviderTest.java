package com.gst.openfire.oidc.auth;

import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@Disabled("This test have to use valid Token")
class OidcAuthProviderTest {

    private OidcAuthProvider oidcAuthProvider;

    @BeforeEach
    void setup() {
        oidcAuthProvider = new OidcAuthProvider();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"PasswordIsNull, admin, null",
        "PasswordIsEmpty, 258868686868,  "
    })
    void testAuthenticate_InvalidPassword_ShouldThrowUnauthorizedException(String testName,
                                                                           String username,
                                                                           String password) {

        Assertions.assertThrows(UnauthorizedException.class, () -> oidcAuthProvider.authenticate(username, password));
    }
}