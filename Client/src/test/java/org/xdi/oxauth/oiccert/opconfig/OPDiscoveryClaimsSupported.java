package org.xdi.oxauth.oiccert.opconfig;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.client.*;

import java.net.URISyntaxException;

import static org.testng.Assert.*;

/**
 * Test ID: OP-Discovery-claims_supported
 * Test description: Verify that claims_supported is published [Config, Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPDiscoveryClaimsSupported {

    @Parameters({"swdResource"})
    @Test
    public void opDiscoveryClaimsSupported(final String swdResource) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Discovery-claims_supported");
        System.out.println("Test description: Verify that claims_supported is published [Config, Dynamic]");
        System.out.println("#######################################################");

        OpenIdConnectDiscoveryClient openIdConnectDiscoveryClient = new OpenIdConnectDiscoveryClient(swdResource);
        OpenIdConnectDiscoveryResponse openIdConnectDiscoveryResponse = openIdConnectDiscoveryClient.exec();

        ClientUtils.showClient(openIdConnectDiscoveryClient);
        assertEquals(openIdConnectDiscoveryResponse.getStatus(), 200);
        assertNotNull(openIdConnectDiscoveryResponse.getSubject());
        assertTrue(openIdConnectDiscoveryResponse.getLinks().size() > 0);

        String configurationEndpoint = openIdConnectDiscoveryResponse.getLinks().get(0).getHref() +
                "/.well-known/openid-configuration";

        System.out.println("OpenID Connect Configuration");

        OpenIdConfigurationClient openIdConfigurationClient = new OpenIdConfigurationClient(configurationEndpoint);
        OpenIdConfigurationResponse openIdConfigurationResponse = openIdConfigurationClient.execOpenIdConfiguration();

        ClientUtils.showClient(openIdConfigurationClient);
        // Checks that the HTTP response status is 200
        assertEquals(openIdConfigurationResponse.getStatus(), 200);
        // Check that the claims_supported discovery metadata value is in the provider_info
        assertTrue(openIdConfigurationResponse.getClaimsSupported().size() > 0);
    }
}
