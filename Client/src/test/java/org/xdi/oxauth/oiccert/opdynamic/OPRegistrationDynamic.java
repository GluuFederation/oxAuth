package org.xdi.oxauth.oiccert.opdynamic;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.RegisterClient;
import org.xdi.oxauth.client.RegisterRequest;
import org.xdi.oxauth.client.RegisterResponse;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import java.net.URISyntaxException;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test ID: OP-Registration-Dynamic
 * Test description: Client registration request [Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPRegistrationDynamic extends BaseTest {

    @Parameters({"redirectUris", "clientJwksUri", "postLogoutRedirectUri"})
    @Test
    public void opRegistrationDynamic(final String redirectUris, final String clientJwksUri, final String postLogoutRedirectUri) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Registration-Dynamic");
        System.out.println("Test description: Client registration request [Dynamic]");
        System.out.println("#######################################################");

        // Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setGrantTypes(Arrays.asList(GrantType.AUTHORIZATION_CODE));
        registerRequest.setPostLogoutRedirectUris(Arrays.asList(postLogoutRedirectUri));
        registerRequest.setResponseTypes(Arrays.asList(ResponseType.CODE));
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        // Checks that the HTTP response status is 200
        assertEquals(registerResponse.getStatus(), 200);
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getRegistrationClientUri());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());
    }
}
