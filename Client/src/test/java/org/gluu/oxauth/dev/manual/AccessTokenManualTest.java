package org.gluu.oxauth.dev.manual;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.AuthorizationRequest;
import org.gluu.oxauth.client.AuthorizationResponse;
import org.gluu.oxauth.model.common.ResponseType;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertNotNull;

/**
 * @author Yuriy Zabrovarnyy
 */
public class AccessTokenManualTest extends BaseTest {

    @Parameters({"userId", "userSecret", "redirectUri", "clientId"})
    @Test
    public void accessTokenExpiration(final String userId, final String userSecret, final String redirectUri, String clientId) throws Exception {
        showTitle("accessTokenExpiration");

        // Request authorization and receive the authorization code.
        String nonce = UUID.randomUUID().toString();
        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN, ResponseType.TOKEN);
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email", "phone", "user_name");
        AuthorizationResponse authorizationResponse = requestAuthorization(userId, userSecret, redirectUri, responseTypes, scopes, clientId, nonce);

        String accessToken = authorizationResponse.getAccessToken();

        System.out.println("access_token: " + accessToken);

        for (int i = 0; i < 100; i++) {
            requestUserInfo(accessToken);

            sleepSeconds(10);

            System.out.println("Obtained user info successfully, seconds: " + ((i + 1) * 10));
        }
    }

    private static void sleepSeconds(int i) throws InterruptedException {
        Thread.sleep(i * 1000);
    }

    private AuthorizationResponse requestAuthorization(final String userId, final String userSecret, final String redirectUri,
                                                       List<ResponseType> responseTypes, List<String> scopes, String clientId, String nonce) {
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getCode(), "The authorization code is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");
        assertNotNull(authorizationResponse.getScope(), "The scope is null");
        return authorizationResponse;
    }
}
