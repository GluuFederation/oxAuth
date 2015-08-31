package org.xdi.oxauth.oiccert.opdynamic;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.common.AuthenticationMethod;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.crypto.signature.RSAPrivateKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.xdi.oxauth.model.register.RegisterRequestParam.SCOPES;

/**
 * Test ID: OP-Registration-jwks_uri
 * Test description: Uses keys registered with jwks_uri value [Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPRegistrationJwksUri extends BaseTest {

    @Parameters({"redirectUris", "postLogoutRedirectUri", "clientJwksUri", "userId", "userSecret", "redirectUri",
            "RS256_modulus", "RS256_privateExponent"})
    @Test
    public void opRegistrationJwksUri(
            final String redirectUris, final String postLogoutRedirectUri, final String clientJwksUri,
            final String userId, final String userSecret, final String redirectUri, final String modulus,
            final String privateExponent) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Registration-jwks_uri");
        System.out.println("Test description: Uses keys registered with jwks_uri value [Dynamic]");
        System.out.println("#######################################################");

        // 1. Dynamic Registration
        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.PRIVATE_KEY_JWT);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.AUTHORIZATION_CODE));
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setJwksUri(clientJwksUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        ClientUtils.showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 200);
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());
        assertNotNull(registerResponse.getClaims().get(SCOPES.toString()));

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        List<String> scopes = Arrays.asList("openid");
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, null);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getCode());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String authorizationCode = authorizationResponse.getCode();

        // 3. Get Access Token
        RSAPrivateKey privateKey = new RSAPrivateKey(modulus, privateExponent);
        TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
        tokenRequest.setCode(authorizationCode);
        tokenRequest.setRedirectUri(redirectUri);
        tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_JWT);
        tokenRequest.setAlgorithm(SignatureAlgorithm.RS256);
        tokenRequest.setKeyId("RS256SIG");
        tokenRequest.setRsaPrivateKey(privateKey);
        tokenRequest.setAudience(tokenEndpoint);
        tokenRequest.setAuthUsername(clientId);

        TokenClient tokenClient = new TokenClient(tokenEndpoint);
        tokenClient.setRequest(tokenRequest);
        TokenResponse tokenResponse = tokenClient.exec();

        showClient(tokenClient);
        assertEquals(tokenResponse.getStatus(), 200);
        assertNotNull(tokenResponse.getEntity());
        assertNotNull(tokenResponse.getAccessToken());
        assertNotNull(tokenResponse.getExpiresIn());
        assertNotNull(tokenResponse.getTokenType());
        assertNotNull(tokenResponse.getIdToken());
        assertNotNull(tokenResponse.getRefreshToken());
    }
}
