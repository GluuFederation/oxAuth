package org.gluu.oxauth.ws.rs;

import com.google.common.collect.Lists;
import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.*;
import org.gluu.oxauth.model.TClientService;
import org.gluu.oxauth.model.authorize.AuthorizeResponseParam;
import org.gluu.oxauth.model.common.Prompt;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.util.StringUtils;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.testng.Assert.*;

/**
 * @author Yuriy Zabrovarnyy
 */
@RunAsClient
public class EndSessionBackchannelRestServerTest extends BaseTest {

    @ArquillianResource
    private URI url;

    private static RegisterResponse registerResponse;
    private static String idToken;
    private static String sessionId;

    @Parameters({"redirectUris", "postLogoutRedirectUri"})
    @Test
    public void requestEndSessionStep1(final String redirectUris, final String postLogoutRedirectUri) throws Exception {

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app", StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN));
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setBackchannelLogoutUris(Lists.newArrayList(postLogoutRedirectUri));
        registerRequest.addCustomAttribute("oxAuthTrustedClient", "true");

        registerResponse = TClientService.register(registerRequest, url);
    }

    @Parameters({"authorizePath", "userId", "userSecret", "redirectUri"})
    @Test(dependsOnMethods = "requestEndSessionStep1")
    public void requestEndSessionStep2(final String authorizePath, final String userId, final String userSecret,
                                       final String redirectUri) throws Exception {

        final String state = UUID.randomUUID().toString();

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, registerResponse.getClientId(), scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);
        authorizationRequest.getPrompts().add(Prompt.NONE);
        authorizationRequest.setAuthUsername(userId);
        authorizationRequest.setAuthPassword(userSecret);

        Invocation.Builder request = ResteasyClientBuilder.newClient()
                .target(url.toString() + authorizePath + "?" + authorizationRequest.getQueryString()).request();
        request.header("Authorization", "Basic " + authorizationRequest.getEncodedCredentials());
        request.header("Accept", MediaType.TEXT_PLAIN);

        Response response = request.get();
        String entity = response.readEntity(String.class);

        showResponse("requestEndSessionStep2", response, entity);

        assertEquals(response.getStatus(), 302, "Unexpected response code.");
        assertNotNull(response.getLocation(), "Unexpected result: " + response.getLocation());

        if (response.getLocation() != null) {
            try {
                URI uri = new URI(response.getLocation().toString());
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

    @Parameters({"endSessionPath", "postLogoutRedirectUri"})
    @Test(dependsOnMethods = "requestEndSessionStep2")
    public void requestEndSessionStep3(final String endSessionPath, final String postLogoutRedirectUri)
            throws Exception {
        String state = UUID.randomUUID().toString();

        EndSessionRequest endSessionRequest = new EndSessionRequest(idToken, postLogoutRedirectUri, state);
        endSessionRequest.setSessionId(sessionId);

        Invocation.Builder request = ResteasyClientBuilder.newClient()
                .target(url.toString() + endSessionPath + "?" + endSessionRequest.getQueryString()).request();
        request.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);

        Response response = request.get();
        String entity = response.readEntity(String.class);

        showResponse("requestEndSessionStep3", response, entity);

        assertEquals(response.getStatus(), 302, "Unexpected response code.");
        assertNotNull(response.getLocation());
        assertTrue(response.getLocation().toString().contains(postLogoutRedirectUri));
        assertTrue(response.getLocation().toString().contains("state=" + state));
    }
}
