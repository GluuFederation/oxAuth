package org.gluu.oxauth.interop;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.RegisterClient;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.client.RegisterResponse;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.util.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.gluu.oxauth.model.common.GrantType.AUTHORIZATION_CODE;
import static org.gluu.oxauth.model.common.ResponseType.CODE;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * OP-3rd_party-init-login-nohttps
 *
 * @author Javier Rojas Blum
 * @version October 22, 2019
 */
public class Supports3rdPartyInitLoginNoHttps extends BaseTest {

    @Parameters({"redirectUri", "clientJwksUri", "postLogoutRedirectUri"})
    @Test
    public void supports3rdPartyInitLoginNoHttps(final String redirectUri, final String clientJwksUri, final String postLogoutRedirectUri) throws Exception {
        showTitle("supports3rdPartyInitLoginNoHttps");

        // 1. Register Client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUri));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org"));
        registerRequest.setGrantTypes(Arrays.asList(AUTHORIZATION_CODE));
        registerRequest.setResponseTypes(Arrays.asList(CODE));
        registerRequest.setInitiateLoginUri("http://client.example.com/start-3rd-party-initiated-sso");
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_BASIC);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 400, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getEntity(), "The entity is null");
        assertNotNull(registerResponse.getErrorType(), "The error type is null");
        assertNotNull(registerResponse.getErrorDescription(), "The error description is null");
    }
}
