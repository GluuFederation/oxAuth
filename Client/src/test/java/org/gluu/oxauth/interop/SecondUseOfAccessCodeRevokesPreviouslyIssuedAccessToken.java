/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.interop;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.AuthorizationRequest;
import org.gluu.oxauth.client.AuthorizationResponse;
import org.gluu.oxauth.client.RegisterClient;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.client.RegisterResponse;
import org.gluu.oxauth.client.TokenClient;
import org.gluu.oxauth.client.TokenResponse;
import org.gluu.oxauth.client.UserInfoClient;
import org.gluu.oxauth.client.UserInfoResponse;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.util.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * OC5:FeatureTest-Second Use of Access Code Revokes Previously Issued Access Token
 *
 * @author Javier Rojas Blum
 * @version May 14, 2019
 */
public class SecondUseOfAccessCodeRevokesPreviouslyIssuedAccessToken extends BaseTest {

    @Parameters({"userId", "userSecret", "redirectUris", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void secondUseOfAccessCodeRevokesPreviouslyIssuedAccessToken(
            final String userId, final String userSecret, final String redirectUris, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Second Use of Access Code Revokes Previously Issued Access Token");

        List<ResponseType> responseTypes = Arrays.asList(
                ResponseType.CODE,
                ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 200, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization and receive the authorization code.
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getCode(), "The authorization code is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");
        assertNotNull(authorizationResponse.getScope(), "The scope is null");
        assertNotNull(authorizationResponse.getIdToken(), "The id token is null");

        String scope = authorizationResponse.getScope();
        String authorizationCode = authorizationResponse.getCode();

        // 3. Request access token using the authorization code.
        String accessToken;
        String refreshToken;
        {
            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            TokenResponse tokenResponse = tokenClient.execAuthorizationCode(authorizationCode, redirectUri,
                    clientId, clientSecret);

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 200, "Unexpected response code: " + tokenResponse.getStatus());
            assertNotNull(tokenResponse.getEntity(), "The entity is null");
            assertNotNull(tokenResponse.getAccessToken(), "The access token is null");
            assertNotNull(tokenResponse.getTokenType(), "The token type is null");
            assertNotNull(tokenResponse.getRefreshToken(), "The refresh token is null");

            accessToken = tokenResponse.getAccessToken();
            refreshToken = tokenResponse.getRefreshToken();
        }

        // 4. Request user info
        {
            UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
            UserInfoResponse userInfoResponse = userInfoClient.execUserInfo(accessToken);

            showClient(userInfoClient);
            assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.NAME));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.GIVEN_NAME));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.FAMILY_NAME));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.EMAIL));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.ZONEINFO));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.LOCALE));
        }

        // 5. Request access token using the same authorization code one more time. This call must fail.
        {
            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            TokenResponse tokenResponse = tokenClient.execAuthorizationCode(authorizationCode, redirectUri, clientId, clientSecret);

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 400, "Unexpected response code: " + tokenResponse.getStatus());
            assertNotNull(tokenResponse.getEntity(), "The entity is null");
            assertNotNull(tokenResponse.getErrorType(), "The error type is null");
            assertNotNull(tokenResponse.getErrorDescription(), "The error description is null");
        }

        // 6. Request user info. This call must fail.
        {
            UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
            UserInfoResponse userInfoResponse = userInfoClient.execUserInfo(accessToken);

            showClient(userInfoClient);
            assertEquals(userInfoResponse.getStatus(), 401, "Unexpected response code: " + userInfoResponse.getStatus());
            assertNotNull(userInfoResponse.getErrorType(), "Unexpected result: errorType not found");
            assertNotNull(userInfoResponse.getErrorDescription(), "Unexpected result: errorDescription not found");
        }

        // 7. Request new access token using the refresh token. This call must fail too.
        {
            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            TokenResponse tokenResponse = tokenClient.execRefreshToken(scope, refreshToken, clientId, clientSecret);

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 400, "Unexpected response code: " + tokenResponse.getStatus());
            assertNotNull(tokenResponse.getEntity(), "The entity is null");
            assertNotNull(tokenResponse.getErrorType(), "The error type is null");
            assertNotNull(tokenResponse.getErrorDescription(), "The error description is null");
        }
    }
}