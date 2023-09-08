package com.gst.openfire.oidc.auth;

import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserManager;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.verification.VerificationMode;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;

@ExtendWith(MockitoExtension.class)
class OidcAuthProviderTest {

    private OidcAuthProvider authProvider;
    @Mock
    private OidcTokenValidator tokenValidator;
    @Mock
    private UserManager userManager;

    @BeforeEach
    void setup() throws JoseException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (MockedConstruction<OidcAuthProvider> mockedConstruction =
                 Mockito.mockConstruction(OidcAuthProvider.class)) {
            authProvider = Mockito.spy(new OidcAuthProvider());
        }
        Mockito.lenient().doReturn(tokenValidator).when(authProvider).getTokenValidator();
        Mockito.lenient().doReturn(userManager).when(authProvider).getUserManager();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("authenticateCaseValidAccountProvider")
    void testAuthenticate_ValidAccount(String testName, boolean isRegistered, VerificationMode callTimes) throws
        InvalidJwtException, MalformedClaimException, UnauthorizedException {
        String username = "admin";
        String password = "An2404";
        JwtClaims mockedJwtClaims = Mockito.mock(JwtClaims.class);
        Mockito.doReturn(mockedJwtClaims).when(tokenValidator).verifyClaims(password);
        Mockito.doReturn(username)
            .when(mockedJwtClaims).getClaimValue(OidcAuthProvider.USER_CLAIM_NAME, String.class);
        Mockito.doReturn(isRegistered).when(userManager).isRegisteredUser(username);

        authProvider.authenticate(username, password);

        Mockito.verify(tokenValidator).verifyClaims(password);
        Mockito.verify(authProvider, callTimes).importKeycloakUser(mockedJwtClaims);
    }

    public static Stream<Arguments> authenticateCaseValidAccountProvider() {
        return Stream.of(
            Arguments.of("Not registered account _ Should import user", false, Mockito.times(1)),
            Arguments.of("Registered account _ Should not import user", true, Mockito.never())
        );
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