/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.ws.rs;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.AuthorizationRequest;
import org.gluu.oxauth.client.AuthorizationResponse;
import org.gluu.oxauth.client.AuthorizeClient;
import org.gluu.oxauth.client.JwkClient;
import org.gluu.oxauth.client.RegisterClient;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.client.RegisterResponse;
import org.gluu.oxauth.client.TokenClient;
import org.gluu.oxauth.client.TokenRequest;
import org.gluu.oxauth.client.TokenResponse;
import org.gluu.oxauth.client.UserInfoClient;
import org.gluu.oxauth.client.UserInfoResponse;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.common.GrantType;
import org.gluu.oxauth.model.common.Prompt;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.common.SubjectType;
import org.gluu.oxauth.model.crypto.signature.RSAPublicKey;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jws.RSASigner;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.jwt.JwtHeaderName;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.util.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * Functional tests for Sector Identifier URI Verification (HTTP)
 *
 * @author Javier Rojas Blum
 * @version May 7, 2019
 */
public class SectorIdentifierUrlVerificationHttpTest extends BaseTest {

    // Run this test with both pairwiseIdType persistent and algorithmic
    // And ensure shareSubjectIdBetweenClientsWithSameSectorId is set to false
    @Parameters({"redirectUris", "sectorIdentifierUri", "redirectUri", "userId", "userSecret"})
    @Test(enabled = false)
    public void pairwiseSectorIdentifierTypeToPreventSubjectIdentifierCorrelation(
            final String redirectUris, final String sectorIdentifierUri, final String redirectUri,
            final String userId, final String userSecret) throws Exception {
        showTitle("pairwiseSectorIdentifierTypeToPreventSubjectIdentifierCorrelation");

        RegisterResponse registerResponse1 = requestClientRegistration(redirectUris, sectorIdentifierUri);
        RegisterResponse registerResponse2 = requestClientRegistration(redirectUris, sectorIdentifierUri);

        String sub1 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse1.getClientId(),
                registerResponse1.getClientSecret(),
                registerResponse1.getResponseTypes());
        String sub2 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse2.getClientId(),
                registerResponse2.getClientSecret(),
                registerResponse2.getResponseTypes());

        assertNotEquals(sub1, sub2, "Each client must receive a different sub value");

        String sub3 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse1.getClientId(),
                registerResponse1.getClientSecret(),
                registerResponse1.getResponseTypes());
        String sub4 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse2.getClientId(),
                registerResponse2.getClientSecret(),
                registerResponse2.getResponseTypes());

        assertEquals(sub1, sub3, "Same client must receive the same sub value");
        assertEquals(sub2, sub4, "Same client must receive the same sub value");
    }

    // Run this test with both pairwiseIdType persistent and algorithmic
    // And ensure shareSubjectIdBetweenClientsWithSameSectorId is set to true
    @Parameters({"redirectUris", "sectorIdentifierUri", "redirectUri", "userId", "userSecret"})
    @Test(enabled = true)
    public void shareSubjectIdBetweenClientsWithSameSectorId(
            final String redirectUris, final String sectorIdentifierUri, final String redirectUri,
            final String userId, final String userSecret) throws Exception {
        showTitle("shareSubjectIdBetweenClientsWithSameSectorId");

        RegisterResponse registerResponse1 = requestClientRegistration(redirectUris, sectorIdentifierUri);
        RegisterResponse registerResponse2 = requestClientRegistration(redirectUris, sectorIdentifierUri);

        String sub1 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse1.getClientId(),
                registerResponse1.getClientSecret(),
                registerResponse1.getResponseTypes());
        String sub2 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse2.getClientId(),
                registerResponse2.getClientSecret(),
                registerResponse2.getResponseTypes());

        assertEquals(sub1, sub2, "Each client must share the same sub value");

        String sub3 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse1.getClientId(),
                registerResponse1.getClientSecret(),
                registerResponse1.getResponseTypes());
        String sub4 = requestAuthorizationCodeWithPairwiseSectorIdentifierType(redirectUri, userId, userSecret,
                registerResponse2.getClientId(),
                registerResponse2.getClientSecret(),
                registerResponse2.getResponseTypes());

        assertEquals(sub1, sub3, "Same client must receive the same sub value");
        assertEquals(sub2, sub4, "Same client must receive the same sub value");
    }

    public RegisterResponse requestClientRegistration(
            final String redirectUris, final String sectorIdentifierUri) {
        List<ResponseType> responseTypes = Arrays.asList(
                ResponseType.CODE,
                ResponseType.ID_TOKEN);

        // Register client with Sector Identifier URL
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSubjectType(SubjectType.PAIRWISE);
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
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        return registerResponse;
    }

    public String requestAuthorizationCodeWithPairwiseSectorIdentifierType(
            final String redirectUri, final String userId, final String userSecret,
            final String clientId, final String clientSecret, final List<ResponseType> responseTypes) throws Exception {

        // 1. Request authorization and receive the authorization code.
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);
        authorizationRequest.getPrompts().add(Prompt.NONE);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getCode(), "The authorization code is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");
        assertNotNull(authorizationResponse.getScope(), "The scope is null");
        assertEquals(authorizationResponse.getState(), state);

        String authorizationCode = authorizationResponse.getCode();
        String idToken = authorizationResponse.getIdToken();

        // 2. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.CODE_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));

        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);

        assertTrue(rsaSigner.validate(jwt));

        String sub = jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER);

        // 3. Request access token using the authorization code.
        TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
        tokenRequest.setCode(authorizationCode);
        tokenRequest.setRedirectUri(redirectUri);
        tokenRequest.setAuthUsername(clientId);
        tokenRequest.setAuthPassword(clientSecret);
        tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_POST);

        TokenClient tokenClient = new TokenClient(tokenEndpoint);
        tokenClient.setRequest(tokenRequest);
        TokenResponse tokenResponse = tokenClient.exec();

        showClient(tokenClient);
        assertEquals(tokenResponse.getStatus(), 200, "Unexpected response code: " + tokenResponse.getStatus());
        assertNotNull(tokenResponse.getEntity(), "The entity is null");
        assertNotNull(tokenResponse.getAccessToken(), "The access token is null");
        assertNotNull(tokenResponse.getExpiresIn(), "The expires in value is null");
        assertNotNull(tokenResponse.getTokenType(), "The token type is null");
        assertNotNull(tokenResponse.getRefreshToken(), "The refresh token is null");

        String accessToken = tokenResponse.getAccessToken();

        // 4. Request user info
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

        return sub;
    }

    @Parameters({"redirectUris", "redirectUri", "userId", "userSecret"})
    @Test
    public void publicSectorIdentifierType(
            final String redirectUris, final String redirectUri, final String userId, final String userSecret) throws Exception {
        showTitle("publicSectorIdentifierType");

        String sub1 = requestAuthorizationCodeWithPublicSectorIdentifierType(redirectUris, redirectUri, userId, userSecret);
        String sub2 = requestAuthorizationCodeWithPublicSectorIdentifierType(redirectUris, redirectUri, userId, userSecret);

        assertEquals(sub1, sub2, "Each client must receive the same sub value");
    }

    public String requestAuthorizationCodeWithPublicSectorIdentifierType(
            final String redirectUris, final String redirectUri, final String userId, final String userSecret) throws Exception {
        List<ResponseType> responseTypes = Arrays.asList(
                ResponseType.CODE,
                ResponseType.ID_TOKEN);

        // 1. Register client with Sector Identifier URL
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_POST);

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
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization and receive the authorization code.
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);
        authorizationRequest.getPrompts().add(Prompt.NONE);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getCode(), "The authorization code is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");
        assertNotNull(authorizationResponse.getScope(), "The scope is null");
        assertEquals(authorizationResponse.getState(), state);

        String authorizationCode = authorizationResponse.getCode();
        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.CODE_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));

        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);

        assertTrue(rsaSigner.validate(jwt));

        String sub = jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER);

        // 4. Request access token using the authorization code.
        TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
        tokenRequest.setCode(authorizationCode);
        tokenRequest.setRedirectUri(redirectUri);
        tokenRequest.setAuthUsername(clientId);
        tokenRequest.setAuthPassword(clientSecret);
        tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_POST);

        TokenClient tokenClient = new TokenClient(tokenEndpoint);
        tokenClient.setRequest(tokenRequest);
        TokenResponse tokenResponse = tokenClient.exec();

        showClient(tokenClient);
        assertEquals(tokenResponse.getStatus(), 200, "Unexpected response code: " + tokenResponse.getStatus());
        assertNotNull(tokenResponse.getEntity(), "The entity is null");
        assertNotNull(tokenResponse.getAccessToken(), "The access token is null");
        assertNotNull(tokenResponse.getExpiresIn(), "The expires in value is null");
        assertNotNull(tokenResponse.getTokenType(), "The token type is null");
        assertNotNull(tokenResponse.getRefreshToken(), "The refresh token is null");

        String accessToken = tokenResponse.getAccessToken();

        // 5. Request user info
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

        return sub;
    }

    @Parameters({"redirectUris"})
    @Test
    public void sectorIdentifierUrlVerificationFail1(final String redirectUris) throws Exception {
        showTitle("sectorIdentifierUrlVerificationFail1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
        registerRequest.setSectorIdentifierUri("https://INVALID_SECTOR_IDENTIFIER_URL");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"sectorIdentifierUri"})
    @Test
    public void sectorIdentifierUrlVerificationFail2(final String sectorIdentifierUri) throws Exception {
        showTitle("sectorIdentifierUrlVerificationFail2");

        String redirectUris = "https://INVALID_REDIRECT_URI https://client.example.com/cb https://client.example.com/cb1 https://client.example.com/cb2";

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    /**
     * Register with pairwise Subject Type and without Sector Identifier URI must fail because there are multiple
     * hostnames in the Redirect URI list.
     */
    @Parameters({"redirectUris"})
    @Test
    public void sectorIdentifierUrlVerificationFail3(final String redirectUris) throws Exception {
        showTitle("sectorIdentifierUrlVerificationFail3");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setSubjectType(SubjectType.PAIRWISE);
        registerRequest.setSectorIdentifierUri(null);

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