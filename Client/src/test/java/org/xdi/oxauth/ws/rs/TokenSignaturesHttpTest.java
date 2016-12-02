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
import org.xdi.oxauth.model.common.Prompt;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.crypto.OxAuthCryptoProvider;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.jws.HMACSigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtHeaderName;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.JwtUtil;
import org.xdi.oxauth.model.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.*;

/**
 * @author Javier Rojas Blum
 * @version November 2, 2016
 */
public class TokenSignaturesHttpTest extends BaseTest {

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenHS256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenHS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS256);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

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
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        HMACSigner hmacSigner = new HMACSigner(SignatureAlgorithm.HS256, clientSecret);
        assertTrue(hmacSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenHS384(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenHS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS384);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

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
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        HMACSigner hmacSigner = new HMACSigner(SignatureAlgorithm.HS384, clientSecret);
        assertTrue(hmacSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenHS512(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenHS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS512);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest request = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        request.setState(state);
        request.setAuthUsername(userId);
        request.setAuthPassword(userSecret);
        request.getPrompts().add(Prompt.NONE);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(request);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        HMACSigner hmacSigner = new HMACSigner(SignatureAlgorithm.HS512, clientSecret);
        assertTrue(hmacSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenRS256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenRS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS256);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

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
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.RS256);
        assertTrue(validJwt);
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenRS384(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenRS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS384);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

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
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.RS384);
        assertTrue(validJwt);
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenRS512(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenRS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS512);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

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
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.RS512);
        assertTrue(validJwt);
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenES256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenES256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.getPrompts().add(Prompt.NONE);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.ES256);
        assertTrue(validJwt);
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenES384(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenES384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES384);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.getPrompts().add(Prompt.NONE);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.ES384);
        assertTrue(validJwt);
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void requestAuthorizationIdTokenES512(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("requestAuthorizationIdTokenES512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES512);
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");
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
        List<String> scopes = Arrays.asList(
                "openid",
                "profile",
                "address",
                "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.getPrompts().add(Prompt.NONE);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);
        AuthorizationResponse authorizationResponse = authorizeClient.exec();

        showClient(authorizeClient);
        assertEquals(authorizationResponse.getStatus(), 302, "Unexpected response code: " + authorizationResponse.getStatus());
        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        String keyId = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), keyId,
                jwkResponse.getJwks().toJSONObject(), null, SignatureAlgorithm.ES512);
        assertTrue(validJwt);
    }

    @Test
    public void printAlgorithmsAndProviders() {
        showTitle("printAlgorithmsAndProviders");

        JwtUtil.printAlgorithmsAndProviders();
    }

    @Test
    public void hs256() throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            showTitle("hs256");

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";
            String secret = "071d68a5-9eb0-47fb-8608-f54a0d9c8ede";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
            String encodedSignature = cryptoProvider.sign(signingInput, null, secret, SignatureAlgorithm.HS256);

            System.out.println("Encoded Signature: " + encodedSignature);
            assertEquals(encodedSignature, "BQwm1HCz0cjHYbulWMumkhZgyb2dD93uScXmC6Fv8Ik");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test
    public void hs384() throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            showTitle("hs384");

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";
            String secret = "071d68a5-9eb0-47fb-8608-f54a0d9c8ede";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
            String encodedSignature = cryptoProvider.sign(signingInput, null, secret, SignatureAlgorithm.HS384);

            System.out.println("Encoded Signature: " + encodedSignature);
            assertEquals(encodedSignature, "pe7gU1XxroqizSzucuHOor36L-M9_XPZ7KZcR6JW6xQAa2fmTLSDCc02fNER9atB");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test
    public void hs512() throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            showTitle("hs512");

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";
            String secret = "071d68a5-9eb0-47fb-8608-f54a0d9c8ede";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider();
            String encodedSignature = cryptoProvider.sign(signingInput, null, secret, SignatureAlgorithm.HS512);

            System.out.println("Encoded Signature: " + encodedSignature);
            assertEquals(encodedSignature, "IZsXiRrRfP9eNFj6snm_MGEnrtfvX8vOF43Z-FuFkRj29y0WUaPR50IXRDI5uGatJvVdr_i7eJCJ4N_EwwrIhQ");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "RS256_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testRS256(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidKeySpecException, IllegalBlockSizeException, IOException, NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test RS256");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.RS256);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.RS256);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "RS384_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testRS384(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidKeySpecException, IllegalBlockSizeException, IOException, NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test RS384");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.RS384);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.RS384);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "RS512_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testRS512(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidKeySpecException, IllegalBlockSizeException, IOException, NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test RS512");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.RS512);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.RS512);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "ES256_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testES256(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, IOException,
            NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test ES256");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.ES256);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.ES256);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "ES384_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testES384(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, IOException,
            NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test ES384");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.ES384);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.ES384);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Parameters({"clientJwksUri", "ES512_keyId", "dnName", "keyStoreFile", "keyStoreSecret"})
    @Test
    public void testES512(final String clientJwksUri, final String keyId, final String dnName, final String keyStoreFile, final String keyStoreSecret)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, IOException,
            NoSuchPaddingException, BadPaddingException {
        try {
            showTitle("Test ES512");

            JwkClient jwkClient = new JwkClient(clientJwksUri);
            JwkResponse jwkResponse = jwkClient.exec();

            String signingInput = "eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ICI2Qm9HN1QwR0RUZ2wiLCAiaWRfdG9rZW4iOiB7Im1heF9hZ2UiOiA4NjQwMH0sICJzdGF0ZSI6ICJTVEFURTAiLCAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8vbG9jYWxob3N0L2NhbGxiYWNrMSIsICJ1c2VyaW5mbyI6IHsiY2xhaW1zIjogeyJuYW1lIjogbnVsbH19LCAiY2xpZW50X2lkIjogIkAhMTExMSEwMDA4IUU2NTQuQjQ2MCIsICJzY29wZSI6IFsib3BlbmlkIl0sICJyZXNwb25zZV90eXBlIjogWyJjb2RlIl19";

            OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, null, SignatureAlgorithm.ES512);

            System.out.println("Encoded Signature: " + encodedSignature);

            boolean signatureVerified = cryptoProvider.verifySignature(
                    signingInput, encodedSignature, keyId, jwkResponse.getJwks().toJSONObject(), null,
                    SignatureAlgorithm.ES512);
            assertTrue(signatureVerified, "Invalid signature");
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @Test
    public void getMessageDigestSHA256() {
        showTitle("sha256");

        try {
            String input = "The quick brown fox jumps over the lazy dog";
            System.out.println("Input: " + input);

            byte[] digest = JwtUtil.getMessageDigestSHA256(input);

            BigInteger result = new BigInteger(1, digest);
            BigInteger expectedResult = new BigInteger("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", 16);

            System.out.println("Result  : " + result);
            System.out.println("Expected: " + expectedResult);

            assertEquals(result, expectedResult);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void getMessageDigestSHA384() {
        showTitle("sha384");

        try {
            String input = "The quick brown fox jumps over the lazy dog";
            System.out.println("Input: " + input);

            byte[] digest = JwtUtil.getMessageDigestSHA384(input);

            BigInteger result = new BigInteger(1, digest);
            BigInteger expectedResult = new BigInteger("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", 16);

            System.out.println("Result   : " + result);
            System.out.println("Expected : " + expectedResult);

            assertEquals(result, expectedResult);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void getMessageDigestSHA512() {
        showTitle("sha512");

        try {
            String input = "The quick brown fox jumps over the lazy dog";
            System.out.println("Input: " + input);

            byte[] digest = JwtUtil.getMessageDigestSHA512(input);

            BigInteger result = new BigInteger(1, digest);
            BigInteger expectedResult = new BigInteger("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", 16);

            System.out.println("Result   : " + result);
            System.out.println("Expected : " + expectedResult);

            assertEquals(result, expectedResult);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
}