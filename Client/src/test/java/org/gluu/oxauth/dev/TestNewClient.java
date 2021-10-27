package org.gluu.oxauth.dev;

import java.io.IOException;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Response;

import org.gluu.oxauth.client.uma.UmaClientFactory;
import org.gluu.oxauth.client.uma.UmaMetadataService;
import org.gluu.oxauth.client.uma.UmaTokenService;
import org.gluu.oxauth.model.uma.UmaMetadata;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient43Engine;

public class TestNewClient {
	public static void main(String[] args) throws IOException {
		UmaMetadata metadata = UmaClientFactory.instance().createMetadataService("https://jenkins-build.gluu.org/oxauth/restv1/uma2-configuration2", new ApacheHttpClient43Engine()).getMetadata();

		UmaTokenService tokenService = UmaClientFactory.instance().createTokenService(metadata, new ApacheHttpClient43Engine());
		tokenService.requestJwtAuthorizationRpt(null, null, null, null, null, null, null, null, null);
/*
		String openIdProvider = "https://jenkins-build.gluu.org/.well-known/openid-configuration";
		javax.ws.rs.client.Client clientRequest = ClientBuilder.newClient();
      
      Response clientResponse = clientRequest.target(openIdProvider).request().buildGet().invoke();

//      ClientResponse<String> clientResponse = clientRequest.get(String.class);
      int status = clientResponse.getStatus();
      System.out.println(status);
      System.out.println(clientResponse.readEntity(String.class));
*/
	}
}
