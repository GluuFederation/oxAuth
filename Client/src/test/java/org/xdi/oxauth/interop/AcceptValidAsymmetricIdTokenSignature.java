/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.interop;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.crypto.signature.ECDSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.RSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.jws.ECDSASigner;
import org.xdi.oxauth.model.jws.RSASigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtHeaderName;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.*;

/**
 * OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature
 *
 * @author Javier Rojas Blum
 * @version November 2, 2016
 */
public class AcceptValidAsymmetricIdTokenSignature extends BaseTest {

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void acceptValidAsymmetricIdTokenSignatureRS256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature RS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS256);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 200, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);
        assertTrue(rsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "postLogoutRedirectUri", "clientJwksUri"})
    @Test
    public void acceptValidAsymmetricIdTokenSignatureES256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String postLogoutRedirectUri, final String clientJwksUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature es256");

        List<ResponseType> responseTypes = Arrays.asList(
                ResponseType.CODE,
                ResponseType.ID_TOKEN);

        List<GrantType> grantTypes = Arrays.asList(GrantType.AUTHORIZATION_CODE);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, null,
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.setPostLogoutRedirectUris(StringUtils.spaceSeparatedToList(postLogoutRedirectUri));
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setGrantTypes(grantTypes);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 200, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        ECDSASigner ecdsaSigner = new ECDSASigner(SignatureAlgorithm.ES256, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }
}