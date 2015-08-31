package org.xdi.oxauth.oiccert.opdynamic;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.ClientUtils;
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
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test ID: OP-Registration-Sector-Bad
 * Test description: Incorrect registration of sector_identifier_uri [Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPRegistrationSectorBad extends BaseTest {

    @Parameters({"redirectUris", "postLogoutRedirectUri", "clientJwksUri", "badSectorIdentifierUri"})
    @Test
    public void opRegistrationSectorBad(
            final String redirectUris, final String postLogoutRedirectUri, final String clientJwksUri,
            final String badSectorIdentifierUri) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Registration-Sector-Bad");
        System.out.println("Test description: Incorrect registration of sector_identifier_uri [Dynamic]");
        System.out.println("#######################################################");

        // 1. Dynamic Registration
        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE);

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
        registerRequest.setSectorIdentifierUri(badSectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        ClientUtils.showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 400);
        assertNotNull(registerResponse.getErrorType());
        assertNotNull(registerResponse.getErrorDescription());
    }
}
