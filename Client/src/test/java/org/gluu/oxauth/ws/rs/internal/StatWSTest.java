package org.gluu.oxauth.ws.rs.internal;

import static org.testng.Assert.assertTrue;

import org.gluu.oxauth.BaseTest;
import org.gluu.oxauth.client.service.ClientFactory;
import org.gluu.oxauth.client.service.StatService;
import org.gluu.oxauth.client.uma.wrapper.UmaClient;
import org.gluu.oxauth.model.uma.wrapper.Token;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @author Yuriy Zabrovarnyy
 */
public class StatWSTest extends BaseTest {

    @Test(enabled = false)
    @Parameters({"umaPatClientId", "umaPatClientSecret"})
    public void stat(final String umaPatClientId, final String umaPatClientSecret) throws Exception {
        final Token authorization = UmaClient.requestPat(tokenEndpoint, umaPatClientId, umaPatClientSecret);

        final StatService service = ClientFactory.instance().createStatService(issuer + "/oxauth/restv1/internal/stat");
        final JsonNode node = service.stat("Bearer " + authorization.getAccessToken(), "202101", null);
        assertTrue(node != null && node.hasNonNull("response"));
    }

    @Test(enabled = false)
    @Parameters({"umaPatClientId", "umaPatClientSecret"})
    public void statPost(final String umaPatClientId, final String umaPatClientSecret) throws Exception {
        final Token authorization = UmaClient.requestPat(tokenEndpoint, umaPatClientId, umaPatClientSecret);
        final StatService service = ClientFactory.instance().createStatService(issuer + "/oxauth/restv1/internal/stat");
        final JsonNode node = service.statPost(authorization.getAccessToken(), "202101", null);
        assertTrue(node != null && node.hasNonNull("response"));
    }
}
