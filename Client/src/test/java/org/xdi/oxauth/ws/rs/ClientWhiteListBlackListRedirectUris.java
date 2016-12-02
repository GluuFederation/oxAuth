/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ws.rs;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.RegisterClient;
import org.xdi.oxauth.client.RegisterRequest;
import org.xdi.oxauth.client.RegisterResponse;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;
import org.xdi.oxauth.model.util.URLPatternList;

import javax.ws.rs.HttpMethod;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;
import static org.xdi.oxauth.model.register.RegisterRequestParam.SCOPES;

/**
 * @author Javier Rojas Blum
 * @version November 2, 2016
 */
public class ClientWhiteListBlackListRedirectUris extends BaseTest {

    private String registrationAccessToken1;
    private String registrationClientUri1;

    @Test
    public void testUrlPatterList() {
        showTitle("testUrlPatterList");

        List<String> urlPatterns = Arrays.asList(
                "*.gluu.org/foo*bar",
                "https://example.org/foo/bar.html",
                "*.attacker.com/*");

        URLPatternList urlPatternList = new URLPatternList(urlPatterns);
        assertFalse(urlPatternList.isUrlListed("gluu.org"));
        assertFalse(urlPatternList.isUrlListed("www.gluu.org"));
        assertTrue(urlPatternList.isUrlListed("http://gluu.org/foo/bar"));
        assertTrue(urlPatternList.isUrlListed("https://mail.gluu.org/foo/bar"));
        assertTrue(urlPatternList.isUrlListed("http://www.gluu.org/foobar"));
        assertTrue(urlPatternList.isUrlListed("https://www.gluu.org/foo/baz/bar"));
        assertFalse(urlPatternList.isUrlListed("http://example.org"));
        assertFalse(urlPatternList.isUrlListed("http://example.org/foo/bar.html"));
        assertTrue(urlPatternList.isUrlListed("https://example.org/foo/bar.html"));
        assertTrue(urlPatternList.isUrlListed("http://attacker.com"));
        assertTrue(urlPatternList.isUrlListed("https://www.attacker.com"));
        assertTrue(urlPatternList.isUrlListed("https://www.attacker.com/foo/bar"));
    }

    @Test
    public void requestClientAssociateInBlackList() throws Exception {
        showTitle("requestClientAssociateInBlackList");

        final String redirectUris = "https://www.attacker.com";

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        RegisterResponse response = registerClient.execRegister(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"redirectUris", "sectorIdentifierUri"})
    @Test
    public void requestClientAssociate(final String redirectUris, final String sectorIdentifierUri) throws Exception {
        showTitle("requestClientAssociate");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        registerClient.setExecutor(clientExecutor(true));
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());
        assertNotNull(response.getClaims().get(SCOPES.toString()));

        registrationAccessToken1 = response.getRegistrationAccessToken();
        registrationClientUri1 = response.getRegistrationClientUri();
    }

    @Test(dependsOnMethods = "requestClientAssociate")
    public void requestClientUpdate() throws Exception {
        showTitle("requestClientUpdate");

        final String redirectUris = "https://www.attacker.com";

        final RegisterRequest registerRequest = new RegisterRequest(registrationAccessToken1);
        registerRequest.setHttpMethod(HttpMethod.PUT);
        registerRequest.setRedirectUris(StringUtils.spaceSeparatedToList(redirectUris));

        final RegisterClient registerClient = new RegisterClient(registrationClientUri1);
        registerClient.setRequest(registerRequest);
        registerClient.setExecutor(clientExecutor(true));
        final RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }
}