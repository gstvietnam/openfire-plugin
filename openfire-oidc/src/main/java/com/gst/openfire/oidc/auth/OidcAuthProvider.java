package com.gst.openfire.oidc.auth;

import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserManager;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcAuthProvider implements AuthProvider {
    static final String USER_CLAIM_NAME = "preferred_username";

    private static Logger logger = LoggerFactory.getLogger(OidcAuthProvider.class);

    public OidcAuthProvider() {
    }

    @Override
    public void authenticate(final String username, final String password) throws UnauthorizedException {
        if (password == null || password.isEmpty()) {
            throw new UnauthorizedException();
        }
        try {
            logger.info("trying to login using {}/{}", username, password);
            JwtClaims jwtClaims = getTokenValidator().verifyToken(password);
            String preferredUsername = jwtClaims.getClaimValue(USER_CLAIM_NAME, String.class);
            if (!getUserManager().isRegisteredUser(preferredUsername)) {
                importKeycloakUser(jwtClaims);
            }
        } catch (Exception e) {
            logger.info("authentication failed: {}", e.getMessage(), e);
            throw new UnauthorizedException(e.getMessage());
        }
    }

    void importKeycloakUser(JwtClaims jwtClaims) {
        try {
            String username = jwtClaims.getClaimValue(USER_CLAIM_NAME, String.class);
            String password = "keycloakuser";
            getUserManager().createUser(username, password, null, null);
            logger.info("imported user from keycloak using username={}, password={}", username, password);
        } catch (MalformedClaimException | UserAlreadyExistsException e) {
            logger.error("failed to import keycloak user" + e.getMessage(), e);
        }

    }

    @Override
    public String getPassword(final String username) throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setPassword(final String username, final String password)
        throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean supportsPasswordRetrieval() {
        return false;
    }

    @Override
    public boolean isScramSupported() {
        return false;
    }

    @Override
    public String getSalt(String username) throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getIterations(String username) throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getServerKey(String username) throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getStoredKey(String username) throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    UserManager getUserManager() {
        return UserManager.getInstance();
    }

    OidcTokenValidator getTokenValidator() {
        return new OidcTokenValidator();
    }
}
