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
import org.gluu.oxauth.client.AuthorizeClient;
import org.gluu.oxauth.client.RegisterClient;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.client.RegisterResponse;
import org.gluu.oxauth.client.UserInfoClient;
import org.gluu.oxauth.client.UserInfoResponse;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.crypto.encryption.BlockEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.util.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * OC5:FeatureTest-Can Request and Use Encrypted UserInfo Response
 *
 * @author Javier Rojas Blum
 * @version November 3, 2016
 */
public class CanRequestAndUseEncryptedUserInfoResponse extends BaseTest {

    @Parameters({"userId", "userSecret", "redirectUri", "redirectUris", "sectorIdentifierUri"})
    @Test
    public void canRequestAndUseEncryptedUserInfoResponse(
            final String userId, final String userSecret, final String redirectUri, final String redirectUris,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Can Request and Use Encrypted UserInfo Response");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
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

        // 2. Request authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String accessToken = authorizationResponse.getAccessToken();

        // 3. Request user info
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setSharedKey(clientSecret);
        UserInfoResponse userInfoResponse = userInfoClient.execUserInfo(accessToken);

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.NAME));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.GIVEN_NAME));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.FAMILY_NAME));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.PICTURE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ZONEINFO));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.EMAIL));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.LOCALE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_REGION));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
    }
}