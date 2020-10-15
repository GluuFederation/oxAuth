package org.gluu.oxauth.client;

import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.jwt.JwtHeaderName;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 25/03/2016
 */

public class Asserter {

    private Asserter() {
    }

    public static void assertOk(RegisterResponse registerResponse) {
        assertEquals(registerResponse.getStatus(), 200, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());
    }

    public static void assertIdToken(Jwt idToken, String... claimsPresence) {
        assertNotNull(idToken);
        assertNotNull(idToken.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(idToken.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.OX_OPENID_CONNECT_VERSION));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE));
        assertNotNull(idToken.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_METHOD_REFERENCES));

        if (claimsPresence == null) {
            return;
        }

        for (String claim : claimsPresence) {
            assertNotNull(claim, "Claim " + claim + " is not found in id_token. ");
        }
    }
}
