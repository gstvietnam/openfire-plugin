package com.gst.openfire.oidc.auth;

import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@ExtendWith(MockitoExtension.class)
class OidcAuthProviderTest {

    private OidcAuthProvider authProvider;
    @Mock
    private OidcTokenValidator tokenValidator;
    @Mock
    private UserManager userManager;
    @Mock
    private User mockedUser;

    @BeforeEach
    void setup() throws JoseException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (MockedConstruction<OidcAuthProvider> mockedConstruction =
                   Mockito.mockConstruction(OidcAuthProvider.class)) {
            authProvider = Mockito.spy(new OidcAuthProvider());
        }
        Mockito.lenient().doReturn(tokenValidator).when(authProvider).getTokenValidator();
        Mockito.lenient().doReturn(userManager).when(authProvider).getUserManager();
    }

    @Test
    void testAuthenticate_NotRegisteredAccount_ShouldImportUser() throws
          InvalidJwtException, MalformedClaimException, UnauthorizedException {
        String username = "admin";
        String password = "An2404";
        JwtClaims mockedJwtClaims = Mockito.mock(JwtClaims.class);
        Mockito.doReturn(mockedJwtClaims).when(tokenValidator).verifyClaims(password);
        Mockito.doReturn(username)
              .when(mockedJwtClaims).getClaimValue(OidcAuthProvider.USER_CLAIM_NAME, String.class);
        Mockito.doReturn(false).when(userManager).isRegisteredUser(username);

        authProvider.authenticate(username, password);

        Mockito.verify(tokenValidator).verifyClaims(password);
        Mockito.verify(authProvider).importKeycloakUser(mockedJwtClaims);
    }

    @Test
    void testAuthenticate_RegisteredAccountAndNameNoChange_ShouldNotImportUserAndSetNewName() throws
          InvalidJwtException, MalformedClaimException, UnauthorizedException, UserNotFoundException {
        String username = "admin";
        String password = "An2404";
        JwtClaims mockedJwtClaims = Mockito.mock(JwtClaims.class);
        Mockito.doReturn(mockedJwtClaims).when(tokenValidator).verifyClaims(password);
        Mockito.doReturn(username)
              .when(mockedJwtClaims).getClaimValue(OidcAuthProvider.USER_CLAIM_NAME, String.class);
        Mockito.doReturn(true).when(userManager).isRegisteredUser(username);
        String mockedNewName = "newName";
        Mockito.doReturn(mockedUser).when(userManager).getUser(username);
        Mockito.doReturn(mockedNewName).when(authProvider).getUserClaimFullName(mockedJwtClaims);

        authProvider.authenticate(username, password);

        Mockito.verify(tokenValidator).verifyClaims(password);
        Mockito.verify(authProvider, Mockito.never()).importKeycloakUser(mockedJwtClaims);
        Mockito.verify(mockedUser).setName(mockedNewName);
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