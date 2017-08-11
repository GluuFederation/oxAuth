/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ws.rs;

import com.google.common.collect.Lists;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.seam.mock.EnhancedMockHttpServletRequest;
import org.jboss.seam.mock.EnhancedMockHttpServletResponse;
import org.jboss.seam.mock.ResourceRequestEnvironment;
import org.jboss.seam.mock.ResourceRequestEnvironment.Method;
import org.jboss.seam.mock.ResourceRequestEnvironment.ResourceRequest;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.authorize.AuthorizeResponseParam;
import org.xdi.oxauth.model.common.Prompt;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.testng.Assert.*;
import static org.xdi.oxauth.model.register.RegisterResponseParam.CLIENT_ID;

/**
 * Test cases for the end session web service (embedded)
 *
 * @author Javier Rojas Blum
 * @version August 11, 2017
 */
public class EndSessionRestWebServiceEmbeddedTest extends BaseTest {

    private String clientId;
    private String idToken;
    private String sessionId;

    @Parameters({"registerPath", "redirectUris", "postLogoutRedirectUri"})
    @Test
    public void requestEndSessionStep1(final String registerPath, final String redirectUris,
                                       final String postLogoutRedirectUri) throws Exception {

        new ResourceRequestEnvironment.ResourceRequest(new ResourceRequestEnvironment(this),
                ResourceRequestEnvironment.Method.POST, registerPath) {

            @Override
            protected void prepareRequest(EnhancedMockHttpServletRequest request) {
                try {
                    super.prepareRequest(request);

                    RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                            StringUtils.spaceSeparatedToList(redirectUris));
                    registerRequest.setResponseTypes(Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN));
                    registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
                    registerRequest.setFrontChannelLogoutUris(Lists.newArrayList(postLogoutRedirectUri));
                    registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");

                    request.setContentType(MediaType.APPLICATION_JSON);
                    String registerRequestContent = registerRequest.getJSONParameters().toString(4);
                    request.setContent(registerRequestContent.getBytes());
                } catch (JSONException e) {
                    e.printStackTrace();
                    fail(e.getMessage());
                }
            }

            @Override
            protected void onResponse(EnhancedMockHttpServletResponse response) {
                super.onResponse(response);
                showResponse("requestEndSessionStep1", response);

                assertEquals(response.getStatus(), 200, "Unexpected response code. " + response.getContentAsString());
                assertNotNull(response.getContentAsString(), "Unexpected result: " + response.getContentAsString());
                try {
                    final RegisterResponse registerResponse = RegisterResponse.valueOf(response.getContentAsString());
                    ClientTestUtil.assert_(registerResponse);

                    JSONObject jsonObj = new JSONObject(response.getContentAsString());
                    assertTrue(jsonObj.has(CLIENT_ID.toString()));

                    clientId = jsonObj.getString(CLIENT_ID.toString());
                } catch (JSONException e) {
                    e.printStackTrace();
                    fail(e.getMessage() + "\nResponse was: " + response.getContentAsString());
                }
            }
        }.run();
    }

    @Parameters({"authorizePath", "userId", "userSecret", "redirectUri"})
    @Test(dependsOnMethods = "requestEndSessionStep1")
    public void requestEndSessionStep2(final String authorizePath, final String userId, final String userSecret,
                                       final String redirectUri) throws Exception {

        final String state = UUID.randomUUID().toString();

        new ResourceRequestEnvironment.ResourceRequest(new ResourceRequestEnvironment(this),
                ResourceRequestEnvironment.Method.GET, authorizePath) {

            @Override
            protected void prepareRequest(EnhancedMockHttpServletRequest request) {
                super.prepareRequest(request);

                List<ResponseType> responseTypes = Arrays.asList(
                        ResponseType.TOKEN,
                        ResponseType.ID_TOKEN);
                List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
                String nonce = UUID.randomUUID().toString();

                AuthorizationRequest authorizationRequest = new AuthorizationRequest(
                        responseTypes, clientId, scopes, redirectUri, nonce);
                authorizationRequest.setState(state);
                authorizationRequest.getPrompts().add(Prompt.NONE);
                authorizationRequest.setAuthUsername(userId);
                authorizationRequest.setAuthPassword(userSecret);

                request.addHeader("Authorization", "Basic " + authorizationRequest.getEncodedCredentials());
                request.addHeader("Accept", MediaType.TEXT_PLAIN);
                request.setQueryString(authorizationRequest.getQueryString());
            }

            @Override
            protected void onResponse(EnhancedMockHttpServletResponse response) {
                super.onResponse(response);
                showResponse("requestEndSessionStep2", response);

                assertEquals(response.getStatus(), 302, "Unexpected response code.");
                assertNotNull(response.getHeader("Location"), "Unexpected result: " + response.getHeader("Location"));

                if (response.getHeader("Location") != null) {
                    try {
                        URI uri = new URI(response.getHeader("Location").toString());
                        assertNotNull(uri.getFragment(), "Fragment is null");

                        Map<String, String> params = QueryStringDecoder.decode(uri.getFragment());

                        assertNotNull(params.get(AuthorizeResponseParam.ACCESS_TOKEN), "The access token is null");
                        assertNotNull(params.get(AuthorizeResponseParam.STATE), "The state is null");
                        assertNotNull(params.get(AuthorizeResponseParam.TOKEN_TYPE), "The token type is null");
                        assertNotNull(params.get(AuthorizeResponseParam.EXPIRES_IN), "The expires in value is null");
                        assertNotNull(params.get(AuthorizeResponseParam.SCOPE), "The scope must be null");
                        assertNull(params.get("refresh_token"), "The refresh_token must be null");
                        assertEquals(params.get(AuthorizeResponseParam.STATE), state);

                        idToken = params.get(AuthorizeResponseParam.ID_TOKEN);
                        sessionId = params.get(AuthorizeResponseParam.SESSION_ID);
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                        fail("Response URI is not well formed");
                    } catch (Exception e) {
                        e.printStackTrace();
                        fail(e.getMessage());
                    }
                }
            }
        }.run();
    }

    @Parameters({"endSessionPath", "postLogoutRedirectUri"})
    @Test(dependsOnMethods = "requestEndSessionStep2")
    public void requestEndSessionStep3(final String endSessionPath, final String postLogoutRedirectUri) throws Exception {
        new ResourceRequest(new ResourceRequestEnvironment(this), Method.GET, endSessionPath) {

            String state = UUID.randomUUID().toString();

            @Override
            protected void prepareRequest(EnhancedMockHttpServletRequest request) {
                super.prepareRequest(request);
                request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);

                EndSessionRequest endSessionRequest = new EndSessionRequest(idToken, postLogoutRedirectUri, state);
                endSessionRequest.setSessionId(sessionId);

                request.setQueryString(endSessionRequest.getQueryString());
            }

            @Override
            protected void onResponse(EnhancedMockHttpServletResponse response) {
                super.onResponse(response);
                showResponse("requestEndSessionStep3", response);

                assertEquals(response.getStatus(), 200, "Unexpected response code.");
                assertNotNull(response.getContentAsString(), "Unexpected html.");
                assertTrue(response.getContentAsString().contains(postLogoutRedirectUri));
                assertTrue(response.getContentAsString().contains(postLogoutRedirectUri));

            }

//            private void validateNonHttpBasedLogout(EnhancedMockHttpServletResponse response) {
//                if (response.getHeader("Location") != null) {
//                    try {
//                        URI uri = new URI(response.getHeader("Location").toString());
//                        assertNotNull(uri.getQuery(), "The query string is null");
//
//                        Map<String, String> params = QueryStringDecoder.decode(uri.getQuery());
//
//                        assertNotNull(params.get(EndSessionResponseParam.STATE), "The state is null");
//                        assertEquals(params.get(EndSessionResponseParam.STATE), endSessionId);
//                    } catch (URISyntaxException e) {
//                        e.printStackTrace();
//                        fail("Response URI is not well formed");
//                    } catch (Exception e) {
//                        e.printStackTrace();
//                        fail(e.getMessage());
//                    }
//                }
//            }
        }.run();
    }

    @Parameters({"endSessionPath"})
    @Test
    public void requestEndSessionFail1(final String endSessionPath) throws Exception {
        new ResourceRequest(new ResourceRequestEnvironment(this), Method.GET, endSessionPath) {

            @Override
            protected void prepareRequest(EnhancedMockHttpServletRequest request) {
                super.prepareRequest(request);
                request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);

                EndSessionRequest endSessionRequest = new EndSessionRequest(null, null, null);

                request.setQueryString(endSessionRequest.getQueryString());
            }

            @Override
            protected void onResponse(EnhancedMockHttpServletResponse response) {
                super.onResponse(response);
                showResponse("requestEndSessionFail1", response);

                assertEquals(response.getStatus(), 400, "Unexpected response code.");
                assertNotNull(response.getContentAsString(), "Unexpected result: " + response.getContentAsString());
                try {
                    JSONObject jsonObj = new JSONObject(response.getContentAsString());
                    assertTrue(jsonObj.has("error"), "The error type is null");
                    assertTrue(jsonObj.has("error_description"), "The error description is null");
                } catch (JSONException e) {
                    e.printStackTrace();
                    fail(e.getMessage() + "\nResponse was: " + response.getContentAsString());
                }
            }
        }.run();
    }

    @Parameters({"endSessionPath", "postLogoutRedirectUri"})
    @Test
    public void requestEndSessionFail2(final String endSessionPath, final String postLogoutRedirectUri) throws Exception {
        new ResourceRequest(new ResourceRequestEnvironment(this), Method.GET, endSessionPath) {

            @Override
            protected void prepareRequest(EnhancedMockHttpServletRequest request) {
                super.prepareRequest(request);
                request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);

                String endSessionId = UUID.randomUUID().toString();
                EndSessionRequest endSessionRequest = new EndSessionRequest("INVALID_ACCESS_TOKEN", postLogoutRedirectUri, endSessionId);

                request.setQueryString(endSessionRequest.getQueryString());
            }

            @Override
            protected void onResponse(EnhancedMockHttpServletResponse response) {
                super.onResponse(response);
                showResponse("requestEndSessionFail2", response);

                assertEquals(response.getStatus(), 401, "Unexpected response code.");
                assertNotNull(response.getContentAsString(), "Unexpected result: " + response.getContentAsString());
                try {
                    JSONObject jsonObj = new JSONObject(response.getContentAsString());
                    assertTrue(jsonObj.has("error"), "The error type is null");
                    assertTrue(jsonObj.has("error_description"), "The error description is null");
                } catch (JSONException e) {
                    e.printStackTrace();
                    fail(e.getMessage() + "\nResponse was: " + response.getContentAsString());
                }
            }
        }.run();
    }
}