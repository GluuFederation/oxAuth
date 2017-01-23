/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ws.rs;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceErrorResponseType;
import org.xdi.oxauth.model.common.AuthenticationMethod;
import org.xdi.oxauth.model.common.ExtensionGrantType;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.token.TokenErrorResponseType;
import org.xdi.oxauth.model.util.StringUtils;

import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test cases for the Device Flow (HTTP)
 *
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class DeviceFlowHttpTest extends BaseTest {

    @Parameters({"userId", "userSecret", "redirectUris", "sectorIdentifierUri"})
    @Test
    public void deviceAuthorization(final String userId, final String userSecret, final String redirectUris,
                                    final String sectorIdentifierUri) {
        showTitle("deviceAuthorization");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);
        List<String> scopes = Arrays.asList("profile", "address", "email");

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setScopes(scopes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_POST);

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

        // 2. Request device authorization.
        DeviceAuthorizationRequest deviceAuthorizationRequest = new DeviceAuthorizationRequest(clientId, scopes);
        DeviceAuthorizationClient deviceAuthorizationClient = new DeviceAuthorizationClient(deviceAuthorizationEndpoint);
        deviceAuthorizationClient.setRequest(deviceAuthorizationRequest);
        DeviceAuthorizationResponse deviceAuthorizationResponse = deviceAuthorizationClient.exec();

        showClient(deviceAuthorizationClient);
        assertEquals(deviceAuthorizationResponse.getStatus(), 200);
        assertNotNull(deviceAuthorizationResponse.getDeviceCode());
        assertNotNull(deviceAuthorizationResponse.getUserCode());
        assertNotNull(deviceAuthorizationResponse.getVerificationUri());
        assertNotNull(deviceAuthorizationResponse.getExpiresIn());
        assertNotNull(deviceAuthorizationResponse.getInterval());

        String deviceCode = deviceAuthorizationResponse.getDeviceCode();

        {
            // 3. Device Token Request (The Authorization is still pending)
            GrantType grantType = GrantType.fromString(ExtensionGrantType.DEVICE_CODE);
            TokenRequest tokenRequest = new TokenRequest(grantType);
            tokenRequest.setCode(deviceCode);
            tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_POST);
            tokenRequest.setAuthUsername(clientId);
            tokenRequest.setAuthPassword(clientSecret);

            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            tokenClient.setRequest(tokenRequest);
            TokenResponse tokenResponse = tokenClient.exec();

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 401);
            assertEquals(tokenResponse.getErrorType(), TokenErrorResponseType.AUTHORIZATION_PENDING);
        }

        {
            // 4. Device Token Request (Repeat the request too quickly)
            GrantType grantType = GrantType.fromString(ExtensionGrantType.DEVICE_CODE);
            TokenRequest tokenRequest = new TokenRequest(grantType);
            tokenRequest.setCode(deviceCode);
            tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_POST);
            tokenRequest.setAuthUsername(clientId);
            tokenRequest.setAuthPassword(clientSecret);

            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            tokenClient.setRequest(tokenRequest);
            TokenResponse tokenResponse = tokenClient.exec();

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 401);
            assertEquals(tokenResponse.getErrorType(), TokenErrorResponseType.SLOW_DOWN);
        }
    }

    @Parameters({"redirectUris", "sectorIdentifierUri"})
    @Test
    public void deviceAuthorizationFail1(final String redirectUris, final String sectorIdentifierUri) {
        showTitle("deviceAuthorizationFail1");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);
        List<String> scopes = Arrays.asList("profile", "address", "email");

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setScopes(scopes);
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

        // 2. Request device authorization.
        scopes = Arrays.asList("profile", "address", "email", "INVALID_SCOPE");
        DeviceAuthorizationRequest deviceAuthorizationRequest = new DeviceAuthorizationRequest(clientId, scopes);
        DeviceAuthorizationClient deviceAuthorizationClient = new DeviceAuthorizationClient(deviceAuthorizationEndpoint);
        deviceAuthorizationClient.setRequest(deviceAuthorizationRequest);
        DeviceAuthorizationResponse deviceAuthorizationResponse = deviceAuthorizationClient.exec();

        showClient(deviceAuthorizationClient);
        assertEquals(deviceAuthorizationResponse.getStatus(), 400);
        assertEquals(deviceAuthorizationResponse.getErrorType(), AuthorizeDeviceErrorResponseType.INVALID_SCOPE);
        assertNotNull(deviceAuthorizationResponse.getErrorDescription());
    }

    @Test
    public void deviceAuthorizationFail2() {
        showTitle("deviceAuthorizationFail2");

        List<String> scopes = Arrays.asList("profile", "address", "email");

        // 1. Request device authorization.
        DeviceAuthorizationRequest deviceAuthorizationRequest = new DeviceAuthorizationRequest("INVALID_CLIENT_ID", scopes);
        DeviceAuthorizationClient deviceAuthorizationClient = new DeviceAuthorizationClient(deviceAuthorizationEndpoint);
        deviceAuthorizationClient.setRequest(deviceAuthorizationRequest);
        DeviceAuthorizationResponse deviceAuthorizationResponse = deviceAuthorizationClient.exec();

        showClient(deviceAuthorizationClient);
        assertEquals(deviceAuthorizationResponse.getStatus(), 400);
        assertEquals(deviceAuthorizationResponse.getErrorType(), AuthorizeDeviceErrorResponseType.INVALID_REQUEST);
        assertNotNull(deviceAuthorizationResponse.getErrorDescription());
    }

    @Test
    public void deviceAuthorizationFail3() {
        showTitle("deviceAuthorizationFail3");

        List<String> scopes = Arrays.asList("profile", "address", "email");

        // 1. Request device authorization.
        DeviceAuthorizationRequest deviceAuthorizationRequest = new DeviceAuthorizationRequest(null, scopes);
        DeviceAuthorizationClient deviceAuthorizationClient = new DeviceAuthorizationClient(deviceAuthorizationEndpoint);
        deviceAuthorizationClient.setRequest(deviceAuthorizationRequest);
        DeviceAuthorizationResponse deviceAuthorizationResponse = deviceAuthorizationClient.exec();

        showClient(deviceAuthorizationClient);
        assertEquals(deviceAuthorizationResponse.getStatus(), 400);
        assertEquals(deviceAuthorizationResponse.getErrorType(), AuthorizeDeviceErrorResponseType.INVALID_REQUEST);
        assertNotNull(deviceAuthorizationResponse.getErrorDescription());
    }

    @Parameters({"redirectUris", "sectorIdentifierUri"})
    @Test
    public void deviceAuthorizationFail4(final String redirectUris, final String sectorIdentifierUri) {
        showTitle("deviceAuthorizationFail4");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);
        List<String> scopes = Arrays.asList("profile", "address", "email");

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setScopes(scopes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_POST);

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

        // 2. Device Token Request with null Device Code
        GrantType grantType = GrantType.fromString(ExtensionGrantType.DEVICE_CODE);
        TokenRequest tokenRequest = new TokenRequest(grantType);
        tokenRequest.setCode(null);
        tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_POST);
        tokenRequest.setAuthUsername(clientId);
        tokenRequest.setAuthPassword(clientSecret);

        TokenClient tokenClient = new TokenClient(tokenEndpoint);
        tokenClient.setRequest(tokenRequest);
        TokenResponse tokenResponse = tokenClient.exec();

        showClient(tokenClient);
        assertEquals(tokenResponse.getStatus(), 400);
        assertEquals(tokenResponse.getErrorType(), TokenErrorResponseType.INVALID_REQUEST);
        assertNotNull(tokenResponse.getErrorDescription());
    }
}
