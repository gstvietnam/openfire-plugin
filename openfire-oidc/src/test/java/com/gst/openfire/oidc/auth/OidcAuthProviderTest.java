package com.gst.openfire.oidc.auth;

import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserManager;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OidcAuthProviderTest {

    @Spy
    private OidcAuthProvider authProvider;
    @Mock
    private OidcTokenValidator tokenValidator;
    @Mock
    private UserManager userManager;

    @BeforeEach
    void setup() {
        Mockito.lenient().doReturn(tokenValidator).when(authProvider).getTokenValidator();
        Mockito.lenient().doReturn(userManager).when(authProvider).getUserManager();
    }

    @Test
    void testAuthenticate_ValidAccountAndHaveNotRegistered_ShouldImportKeycloakUser() throws InvalidJwtException,
        MalformedClaimException, UnauthorizedException {

        String haveNotRegisteredUsername = "admin";
        String password = "An2404";
        JwtClaims mockedJwtClaims = Mockito.mock(JwtClaims.class);
        Mockito.doReturn(mockedJwtClaims).when(tokenValidator).verifyToken(password);
        Mockito.doReturn(haveNotRegisteredUsername)
            .when(mockedJwtClaims).getClaimValue(OidcAuthProvider.USER_CLAIM_NAME, String.class);
        Mockito.doReturn(false).when(userManager).isRegisteredUser(haveNotRegisteredUsername);

        authProvider.authenticate(haveNotRegisteredUsername, password);

        Mockito.verify(tokenValidator).verifyToken(password);
        Mockito.verify(authProvider).importKeycloakUser(mockedJwtClaims);
    }

    @Test
    void testAuthenticate_RegisteredAccount_ShouldNotImportKeycloakUser() throws InvalidJwtException,
        MalformedClaimException, UnauthorizedException {

        String registeredUsername = "admin";
        String password = "An2404";
        JwtClaims mockedJwtClaims = Mockito.mock(JwtClaims.class);
        Mockito.doReturn(mockedJwtClaims).when(tokenValidator).verifyToken(password);
        Mockito.doReturn(registeredUsername)
            .when(mockedJwtClaims).getClaimValue(OidcAuthProvider.USER_CLAIM_NAME, String.class);
        Mockito.doReturn(true).when(userManager).isRegisteredUser(registeredUsername);

        authProvider.authenticate(registeredUsername, password);

        Mockito.verify(tokenValidator).verifyToken(password);
        Mockito.verify(authProvider, Mockito.never()).importKeycloakUser(mockedJwtClaims);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "PassIsNull, admin, null",
        "PassIsEmpty, admin, "
    })
    void testAuthenticate_InvalidPass_ShouldThrowUnauthorizedException(String testName,
                                                                       String username,
                                                                       String password) {
        Assertions.assertThrowsExactly(UnauthorizedException.class,
            () -> authProvider.authenticate(username, password));
    }
}