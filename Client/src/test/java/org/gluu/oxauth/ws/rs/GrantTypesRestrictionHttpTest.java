/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.ws.rs;

import com.google.common.collect.Lists;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.*;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.common.GrantType;
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
import org.testng.ITestContext;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.gluu.oxauth.model.register.RegisterRequestParam.APPLICATION_TYPE;
import static org.gluu.oxauth.model.register.RegisterRequestParam.SCOPE;
import static org.testng.Assert.*;

/**
 * @author Javier Rojas Blum
 * @version November 29, 2017
 */
public class GrantTypesRestrictionHttpTest extends BaseTest {

    @Test(dataProvider = "grantTypesRestrictionDataProvider")
    public void grantTypesRestriction(
            final List<ResponseType> responseTypes, final List<ResponseType> expectedResponseTypes,
            final List<GrantType> grantTypes, final List<GrantType> expectedGrantTypes,
            final String userId, final String userSecret,
            final String redirectUris, final String redirectUri, final String sectorIdentifierUri,
            final String postLogoutRedirectUri, final String logoutUri) throws Exception {
        showTitle("grantTypesRestriction");

        List<String> scopes = Arrays.asList("openid", "profile", "address", "email", "user_name");

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setGrantTypes(grantTypes);
        registerRequest.setScope(scopes);
        registerRequest.setSubjectType(SubjectType.PAIRWISE);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setFrontChannelLogoutUri(logoutUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 200);
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());
        assertNotNull(registerResponse.getResponseTypes());
        assertTrue(registerResponse.getResponseTypes().containsAll(expectedResponseTypes));
        assertNotNull(registerResponse.getGrantTypes());
        assertTrue(registerResponse.getGrantTypes().containsAll(expectedGrantTypes));

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();
        String registrationAccessToken = registerResponse.getRegistrationAccessToken();
        String registrationClientUri = registerResponse.getRegistrationClientUri();

        // 2. Client read
        RegisterRequest readRequest = new RegisterRequest(registrationAccessToken);

        RegisterClient readClient = new RegisterClient(registrationClientUri);
        readClient.setRequest(readRequest);
        RegisterResponse readResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(readResponse.getStatus(), 200);
        assertNotNull(readResponse.getClientId());
        assertNotNull(readResponse.getClientSecret());
        assertNotNull(readResponse.getRegistrationAccessToken());
        assertNotNull(readResponse.getRegistrationClientUri());
        assertNotNull(readResponse.getClientSecretExpiresAt());
        assertNotNull(readResponse.getClaims().get(APPLICATION_TYPE.toString()));
        assertNotNull(readResponse.getClaims().get(SCOPE.toString()));
        assertNotNull(readResponse.getResponseTypes());
        assertTrue(readResponse.getResponseTypes().containsAll(expectedResponseTypes));
        assertNotNull(readResponse.getGrantTypes());
        assertTrue(readResponse.getGrantTypes().containsAll(expectedGrantTypes));

        // 3. Request authorization
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(expectedResponseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        if (expectedResponseTypes.size() == 0) {
            AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
            authorizeClient.setRequest(authorizationRequest);
            AuthorizationResponse authorizationResponse = authorizeClient.exec();

            showClient(authorizeClient);
            assertEquals(authorizationResponse.getStatus(), 302);
            assertNotNull(authorizationResponse.getLocation());
            assertNotNull(authorizationResponse.getErrorType());
            assertNotNull(authorizationResponse.getErrorDescription());
            assertNotNull(authorizationResponse.getState());

            return;
        }

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        String scope = authorizationResponse.getScope();
        String authorizationCode = null;
        String accessToken = null;
        String idToken = null;
        String refreshToken = null;

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getState());
        assertNotNull(authorizationResponse.getScope());
        if (expectedResponseTypes.contains(ResponseType.CODE)) {
            assertNotNull(authorizationResponse.getCode());

            authorizationCode = authorizationResponse.getCode();
        }
        if (expectedResponseTypes.contains(ResponseType.TOKEN)) {
            assertNotNull(authorizationResponse.getAccessToken());

            accessToken = authorizationResponse.getAccessToken();
        }
        if (expectedResponseTypes.contains(ResponseType.ID_TOKEN)) {
            assertNotNull(authorizationResponse.getIdToken());

            idToken = authorizationResponse.getIdToken();

            // 4. Validate id_token
            Jwt jwt = Jwt.parse(idToken);
            assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
            assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
            assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));

            RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                    jwksUri,
                    jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
            RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);

            assertTrue(rsaSigner.validate(jwt));

            if (expectedResponseTypes.contains(ResponseType.CODE)) {
                assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.CODE_HASH));
                assertTrue(rsaSigner.validateAuthorizationCode(authorizationCode, jwt));
            }
            if (expectedResponseTypes.contains(ResponseType.TOKEN)) {
                assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
                assertTrue(rsaSigner.validateAccessToken(accessToken, jwt));
            }
        }

        if (expectedResponseTypes.contains(ResponseType.CODE)) {
            // 5. Request access token using the authorization code.
            TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
            tokenRequest.setCode(authorizationCode);
            tokenRequest.setRedirectUri(redirectUri);
            tokenRequest.setAuthUsername(clientId);
            tokenRequest.setAuthPassword(clientSecret);
            tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_BASIC);

            TokenClient tokenClient = new TokenClient(tokenEndpoint);
            tokenClient.setRequest(tokenRequest);
            TokenResponse tokenResponse = tokenClient.exec();

            showClient(tokenClient);
            assertEquals(tokenResponse.getStatus(), 200);
            assertNotNull(tokenResponse.getEntity());
            assertNotNull(tokenResponse.getAccessToken());
            assertNotNull(tokenResponse.getExpiresIn());
            assertNotNull(tokenResponse.getTokenType());

            if (expectedGrantTypes.contains(GrantType.REFRESH_TOKEN)) {
                assertNotNull(tokenResponse.getRefreshToken());

                refreshToken = tokenResponse.getRefreshToken();

                // 6. Request new access token using the refresh token.
                TokenClient refreshTokenClient = new TokenClient(tokenEndpoint);
                TokenResponse refreshTokenResponse = refreshTokenClient.execRefreshToken(scope, refreshToken, clientId, clientSecret);

                showClient(refreshTokenClient);
                assertEquals(refreshTokenResponse.getStatus(), 200);
                assertNotNull(refreshTokenResponse.getEntity());
                assertNotNull(refreshTokenResponse.getAccessToken());
                assertNotNull(refreshTokenResponse.getTokenType());
                assertNotNull(refreshTokenResponse.getRefreshToken());
                assertNotNull(refreshTokenResponse.getScope());

                accessToken = refreshTokenResponse.getAccessToken();
            } else {
                assertNull(tokenResponse.getRefreshToken());
            }
        }

        if (accessToken != null) {
            // 7. Request user info
            UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
            UserInfoResponse userInfoResponse = userInfoClient.execUserInfo(accessToken);

            showClient(userInfoClient);
            assertEquals(userInfoResponse.getStatus(), 200);
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.NAME));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.FAMILY_NAME));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.EMAIL));
            assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));

            if (idToken != null) {
                // 8. End session
                String endSessionId = UUID.randomUUID().toString();
                EndSessionRequest endSessionRequest = new EndSessionRequest(idToken, postLogoutRedirectUri, endSessionId);
                endSessionRequest.setSessionId(authorizationResponse.getSessionId());

                EndSessionClient endSessionClient = new EndSessionClient(endSessionEndpoint);
                endSessionClient.setRequest(endSessionRequest);

                EndSessionResponse endSessionResponse = endSessionClient.exec();

                showClient(endSessionClient);
                assertEquals(endSessionResponse.getStatus(), 200);
                assertNotNull(endSessionResponse.getHtmlPage());

                // silly validation of html content returned by server but at least it verifies that logout_uri and post_logout_uri are present
                assertTrue(endSessionResponse.getHtmlPage().contains("<html>"));
                assertTrue(endSessionResponse.getHtmlPage().contains(logoutUri));
                assertTrue(endSessionResponse.getHtmlPage().contains(postLogoutRedirectUri));
                // assertEquals(endSessionResponse.getState(), endSessionId); // commented out, for http-based logout we get html page
            }
        }
    }

    @DataProvider(name = "grantTypesRestrictionDataProvider")
    public Object[][] omittedResponseTypesFailDataProvider(ITestContext context) {
        String userId = context.getCurrentXmlTest().getParameter("userId");
        String userSecret = context.getCurrentXmlTest().getParameter("userSecret");
        String redirectUris = context.getCurrentXmlTest().getParameter("redirectUris");
        String redirectUri = context.getCurrentXmlTest().getParameter("redirectUri");
        String sectorIdentifierUri = context.getCurrentXmlTest().getParameter("sectorIdentifierUri");
        String postLogoutRedirectUri = context.getCurrentXmlTest().getParameter("postLogoutRedirectUri");
        String logoutUri = context.getCurrentXmlTest().getParameter("logoutUri");

        return new Object[][]{
                {
                        Arrays.asList(),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(),
                        Arrays.asList(),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(ResponseType.CODE),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(ResponseType.TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                //
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.REFRESH_TOKEN),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.CLIENT_CREDENTIALS),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.CLIENT_CREDENTIALS),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
                {
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN),
                        Arrays.asList(GrantType.OXAUTH_UMA_TICKET),
                        Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.IMPLICIT, GrantType.OXAUTH_UMA_TICKET),
                        userId, userSecret, redirectUris, redirectUri, sectorIdentifierUri, postLogoutRedirectUri, logoutUri
                },
        };
    }
}
