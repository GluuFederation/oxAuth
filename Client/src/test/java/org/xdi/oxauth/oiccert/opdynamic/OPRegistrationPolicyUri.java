package org.xdi.oxauth.oiccert.opdynamic;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.*;
import static org.xdi.oxauth.model.register.RegisterRequestParam.SCOPES;

/**
 * Test ID: OP-Registration-policy_uri
 * Test description: Registration with policy_uri [Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPRegistrationPolicyUri extends BaseTest {

    @Parameters({"redirectUris", "postLogoutRedirectUri", "clientJwksUri", "redirectUri"})
    @Test
    public void opRegistrationPolicyUri(
            final String redirectUris, final String postLogoutRedirectUri, final String clientJwksUri,
            final String redirectUri) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Registration-policy_uri");
        System.out.println("Test description: Registration with policy_uri [Dynamic]");
        System.out.println("#######################################################");

        // 1. Dynamic Registration
        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);
        String policyUri = "http://www.gluu.org/policy";

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setGrantTypes(Arrays.asList(GrantType.AUTHORIZATION_CODE));
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setPolicyUri(policyUri);

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

        String authorizationRequestUrl = getAuthorizationEndpoint() + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(getAuthorizationEndpoint());
        authorizeClient.setRequest(authorizationRequest);

        try {
            startSelenium();
            driver.navigate().to(authorizationRequestUrl);

            WebElement policy = driver.findElement(By.xpath("//a[@href='" + policyUri + "']"));
            assertNotNull(policy);
        } catch (NoSuchElementException ex) {
            fail("Policy not found");
        } finally {
            stopSelenium();
        }
    }
}
