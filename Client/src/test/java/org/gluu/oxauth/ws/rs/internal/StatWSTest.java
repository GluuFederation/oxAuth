package org.gluu.oxauth.ws.rs.internal;

import com.fasterxml.jackson.databind.JsonNode;
import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.BaseRequest;
import org.gluu.oxauth.client.service.ClientFactory;
import org.gluu.oxauth.client.service.StatService;
import org.gluu.oxauth.client.uma.wrapper.UmaClient;
import org.gluu.oxauth.model.uma.wrapper.Token;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * @author Yuriy Zabrovarnyy
 */
public class StatWSTest extends BaseTest {

    @Test
    @Parameters({"umaPatClientId", "umaPatClientSecret"})
    public void stat(final String umaPatClientId, final String umaPatClientSecret) throws Exception {
        final Token authorization = UmaClient.requestPat(tokenEndpoint, umaPatClientId, umaPatClientSecret);

        final StatService service = ClientFactory.instance().createStatService(issuer + "/oxauth/restv1/internal/stat");
        final JsonNode node = service.stat("Bearer " + authorization.getAccessToken(), "202101");
        assertTrue(node != null && node.hasNonNull("response"));
    }

    @Test
    @Parameters({"umaPatClientId", "umaPatClientSecret"})
    public void statBasic(final String umaPatClientId, final String umaPatClientSecret) throws Exception {
        final StatService service = ClientFactory.instance().createStatService(issuer + "/oxauth/restv1/internal/stat");
        final JsonNode node = service.stat("Basic " + BaseRequest.getEncodedCredentials(umaPatClientId, umaPatClientSecret), "202101");
        assertTrue(node != null && node.hasNonNull("response"));
    }

    @Test
    @Parameters({"umaPatClientId", "umaPatClientSecret"})
    public void statPost(final String umaPatClientId, final String umaPatClientSecret) throws Exception {
        final StatService service = ClientFactory.instance().createStatService(issuer + "/oxauth/restv1/internal/stat");
        final JsonNode node = service.stat(null, "202101", umaPatClientId, umaPatClientSecret);
        assertTrue(node != null && node.hasNonNull("response"));
    }
}
