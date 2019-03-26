/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.RegisterClient;
import org.xdi.oxauth.client.RegisterRequest;
import org.xdi.oxauth.client.RegisterResponse;
import org.xdi.oxauth.model.common.BackchannelTokenDeliveryMode;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.crypto.signature.AsymmetricSignatureAlgorithm;
import org.xdi.oxauth.model.register.ApplicationType;

import java.util.Arrays;

import static org.testng.Assert.*;
import static org.xdi.oxauth.model.register.RegisterRequestParam.*;

/**
 * @author Javier Rojas Blum
 * @version March 25, 2019
 */
public class RegistrationTest extends BaseTest {

    @Parameters({"clientJwksUri"})
    @Test
    public void backchannelTokenDeliveryModePoll1(final String clientJwksUri) {
        showTitle("backchannelTokenDeliveryModePoll1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.POLL);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.POLL.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"sectorIdentifierUri", "clientJwksUri"})
    @Test
    public void backchannelTokenDeliveryModePoll2(final String sectorIdentifierUri, final String clientJwksUri) {
        showTitle("backchannelTokenDeliveryModePoll2");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.POLL);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(JWKS_URI.toString()));
        assertTrue(response.getClaims().containsKey(SECTOR_IDENTIFIER_URI.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.POLL.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Test
    public void backchannelTokenDeliveryModePoll3() {
        showTitle("backchannelTokenDeliveryModePoll3");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.POLL);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.POLL.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"clientJwksUri", "backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePing1(final String clientJwksUri,
                                                  final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePing1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PING.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"sectorIdentifierUri", "clientJwksUri", "backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePing2(final String sectorIdentifierUri, final String clientJwksUri,
                                                  final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePing2");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(JWKS_URI.toString()));
        assertTrue(response.getClaims().containsKey(SECTOR_IDENTIFIER_URI.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PING.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePing3(final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePing3");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PING.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePush1(final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePush1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PUSH);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PUSH.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"sectorIdentifierUri", "backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePush2(final String sectorIdentifierUri, final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePush2");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PUSH);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(SECTOR_IDENTIFIER_URI.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PUSH.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"backchannelClientNotificationEndpoint"})
    @Test
    public void backchannelTokenDeliveryModePush3(final String backchannelClientNotificationEndpoint) {
        showTitle("backchannelTokenDeliveryModePush3");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PUSH);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());

        assertTrue(response.getClaims().containsKey(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_USER_CODE_PARAMETER.toString()));
        assertTrue(response.getClaims().containsKey(BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT.toString()));
        assertEquals(response.getClaims().get(BACKCHANNEL_TOKEN_DELIVERY_MODE.toString()), BackchannelTokenDeliveryMode.PUSH.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG.toString()), AsymmetricSignatureAlgorithm.RS256.getValue());
        assertEquals(response.getClaims().get(BACKCHANNEL_USER_CODE_PARAMETER.toString()), new Boolean(true).toString());
    }

    @Parameters({"clientJwksUri"})
    @Test
    public void registrationFail1(final String clientJwksUri) {
        showTitle("registrationFail1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(null); // Missing backchannel_token_delivery_mode
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"clientJwksUri"})
    @Test
    public void registrationFail2(final String clientJwksUri) {
        showTitle("registrationFail2");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(null); // Missing backchannel_client_notification_endpoint
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"clientJwksUri"})
    @Test
    public void registrationFail3(final String clientJwksUri) {
        showTitle("registration3");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PUSH);
        registerRequest.setBackchannelClientNotificationEndpoint(null); // Missing backchannel_client_notification_endpoint
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"clientJwksUri", "backchannelClientNotificationEndpoint"})
    @Test
    public void registrationFail4(final String clientJwksUri, final String backchannelClientNotificationEndpoint) {
        showTitle("registrationFail4");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList()); // Missing  grant type urn:openid:params:grant-type:ciba

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"clientJwksUri", "backchannelClientNotificationEndpoint"})
    @Test
    public void registrationFail5(final String clientJwksUri, final String backchannelClientNotificationEndpoint) {
        showTitle("registrationFail5");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setGrantTypes(Arrays.asList()); // Missing  grant type urn:openid:params:grant-type:ciba

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.POLL);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"backchannelClientNotificationEndpoint"})
    @Test
    public void registrationFail6(final String backchannelClientNotificationEndpoint) {
        showTitle("registrationFail6");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(null); // Missing jwks_uri
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.PING);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"backchannelClientNotificationEndpoint"})
    @Test
    public void registrationFail7(final String backchannelClientNotificationEndpoint) {
        showTitle("registrationFail7");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", null);
        registerRequest.setJwksUri(null); // Missing jwks_uri
        registerRequest.setGrantTypes(Arrays.asList(GrantType.CIBA));

        registerRequest.setBackchannelTokenDeliveryMode(BackchannelTokenDeliveryMode.POLL);
        registerRequest.setBackchannelClientNotificationEndpoint(backchannelClientNotificationEndpoint);
        registerRequest.setBackchannelAuthenticationRequestSigningAlg(AsymmetricSignatureAlgorithm.RS256);
        registerRequest.setBackchannelUserCodeParameter(true);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }
}
