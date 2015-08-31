package org.xdi.oxauth.oiccert.opconfig;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.model.jwk.JSONWebKey;

import java.net.URISyntaxException;

import static org.testng.Assert.*;

/**
 * Test ID: OP-Discovery-JWKs
 * Test description: Keys in OP JWKs well formed [Config, Dynamic]
 *
 * @author Javier Rojas Blum
 * @version August 31, 2015
 */
public class OPDiscoveryJwks {

    @Parameters({"swdResource"})
    @Test
    public void opDiscoveryJwks(final String swdResource) throws URISyntaxException {
        System.out.println("#######################################################");
        System.out.println("Test ID: OP-Discovery-JWKs");
        System.out.println("Test description: Keys in OP JWKs well formed [Config, Dynamic]");
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
        assertNotNull(openIdConfigurationResponse.getJwksUri());

        String jwksUri = openIdConfigurationResponse.getJwksUri();

        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();

        ClientUtils.showClient(jwkClient);
        // Verifies that the base64 encoded parts of a JWK is in fact base64url encoded and not just base64 encoded
        for (JSONWebKey jsonWebKey : jwkResponse.getKeys()) {
            if (jsonWebKey.getPublicKey().getModulus() != null) {
                assertTrue(!jsonWebKey.getPublicKey().getModulus().contains("="));
                assertTrue(!jsonWebKey.getPublicKey().getModulus().contains("+"));
                assertTrue(!jsonWebKey.getPublicKey().getModulus().contains("/"));
            }
            if (jsonWebKey.getPublicKey().getExponent() != null) {
                assertTrue(!jsonWebKey.getPublicKey().getExponent().contains("="));
                assertTrue(!jsonWebKey.getPublicKey().getExponent().contains("+"));
                assertTrue(!jsonWebKey.getPublicKey().getExponent().contains("/"));
            }
            if (jsonWebKey.getPublicKey().getX() != null) {
                assertTrue(!jsonWebKey.getPublicKey().getX().contains("="));
                assertTrue(!jsonWebKey.getPublicKey().getX().contains("+"));
                assertTrue(!jsonWebKey.getPublicKey().getX().contains("/"));
            }
            if (jsonWebKey.getPublicKey().getY() != null) {
                assertTrue(!jsonWebKey.getPublicKey().getY().contains("="));
                assertTrue(!jsonWebKey.getPublicKey().getY().contains("+"));
                assertTrue(!jsonWebKey.getPublicKey().getY().contains("/"));
            }
        }
    }
}
