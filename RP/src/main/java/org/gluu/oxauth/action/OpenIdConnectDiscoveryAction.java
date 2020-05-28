/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.action;

import org.apache.http.client.HttpClient;
import org.gluu.net.SslDefaultHttpClient;
import org.gluu.net.TrustAllTrustManager;
import org.gluu.oxauth.client.*;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.slf4j.Logger;

import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.Serializable;
import java.net.URISyntaxException;

import static org.gluu.oxauth.model.discovery.WebFingerParam.REL_VALUE;

/**
 * @author Javier Rojas Blum
 * @version December 21, 2019
 */
@Named
@SessionScoped
public class OpenIdConnectDiscoveryAction implements Serializable {

	private static final long serialVersionUID = -7821250358671474997L;

	@Inject
	private Logger log;

	@Inject
	private RegistrationAction registrationAction;

	@Inject
	private AuthorizationAction authorizationAction;

	@Inject
	private BackchannelAuthenticationAction backchannelAuthenticationAction;

	@Inject
	private TokenAction tokenAction;

	@Inject
	private UserInfoAction userInfoAction;

	@Inject
	private CheckSessionAction checkSessionAction;

	@Inject
	private EndSessionAction endSessionAction;

	private String resource;
	private String host;
	private String rel;

	private boolean showResults;
	private boolean acceptUntrustedCertificate;
	private String requestString1;
	private String responseString1;
	private String requestString2;
	private String responseString2;

	public void exec() {
		try {
			ClientExecutor clientExecutor = null;
			if (acceptUntrustedCertificate) {
				HttpClient httpClient = new SslDefaultHttpClient(new TrustAllTrustManager());
				clientExecutor = new ApacheHttpClient4Executor(httpClient);
			}

			OpenIdConnectDiscoveryRequest openIdConnectDiscoveryRequest = new OpenIdConnectDiscoveryRequest(resource);
			host = openIdConnectDiscoveryRequest.getHost();
			rel = REL_VALUE;

			OpenIdConnectDiscoveryClient openIdConnectDiscoveryClient = new OpenIdConnectDiscoveryClient(resource);

			OpenIdConnectDiscoveryResponse openIdConnectDiscoveryResponse;
			if (clientExecutor == null) {
				openIdConnectDiscoveryResponse = openIdConnectDiscoveryClient.exec();
			} else {
				openIdConnectDiscoveryResponse = openIdConnectDiscoveryClient.exec(clientExecutor);
			}

			showResults = true;
			requestString1 = openIdConnectDiscoveryClient.getRequestAsString();
			responseString1 = openIdConnectDiscoveryClient.getResponseAsString();

			if (openIdConnectDiscoveryResponse.getStatus() == 200) {
				String openIdConfigurationUrl = openIdConnectDiscoveryResponse.getLinks().get(0).getHref()
						+ "/.well-known/openid-configuration";
				OpenIdConfigurationClient openIdConfigurationClient = new OpenIdConfigurationClient(
						openIdConfigurationUrl);
				OpenIdConfigurationResponse openIdConfigurationResponse;
				if (clientExecutor == null) {
					openIdConfigurationResponse = openIdConfigurationClient.execOpenIdConfiguration();
				} else {
					openIdConfigurationResponse = openIdConfigurationClient.execOpenIdConfiguration(clientExecutor);
				}

				requestString2 = openIdConfigurationClient.getRequestAsString();
				responseString2 = openIdConfigurationClient.getResponseAsString();

				registrationAction.setRegistrationEndpoint(openIdConfigurationResponse.getRegistrationEndpoint());
				authorizationAction.setAuthorizationEndpoint(openIdConfigurationResponse.getAuthorizationEndpoint());
				authorizationAction.setJwksUri(openIdConfigurationResponse.getJwksUri());
				backchannelAuthenticationAction.setBackchannelAuthenticationEndpoint(openIdConfigurationResponse.getBackchannelAuthenticationEndpoint());
				backchannelAuthenticationAction.setTokenEndpoint(openIdConfigurationResponse.getTokenEndpoint());
				tokenAction.setTokenEndpoint(openIdConfigurationResponse.getTokenEndpoint());
				userInfoAction.setUserInfoEndpoint(openIdConfigurationResponse.getUserInfoEndpoint());
				checkSessionAction.setCheckSessionEndpoint(openIdConfigurationResponse.getCheckSessionIFrame());
				endSessionAction.setEndSessionEndpoint(openIdConfigurationResponse.getEndSessionEndpoint());
			}
		} catch (IllegalArgumentException e) {
			log.error(e.getMessage(), e);
		} catch (URISyntaxException e) {
			log.error(e.getMessage(), e);
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	}

	public String getResource() {
		return resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getRel() {
		return rel;
	}

	public void setRel(String rel) {
		this.rel = rel;
	}

	public boolean isShowResults() {
		return showResults;
	}

	public void setShowResults(boolean showResults) {
		this.showResults = showResults;
	}

	public String getRequestString1() {
		return requestString1;
	}

	public void setRequestString1(String requestString1) {
		this.requestString1 = requestString1;
	}

	public String getResponseString1() {
		return responseString1;
	}

	public void setResponseString1(String responseString1) {
		this.responseString1 = responseString1;
	}

	public String getRequestString2() {
		return requestString2;
	}

	public void setRequestString2(String requestString2) {
		this.requestString2 = requestString2;
	}

	public String getResponseString2() {
		return responseString2;
	}

	public void setResponseString2(String responseString2) {
		this.responseString2 = responseString2;
	}

	public boolean isAcceptUntrustedCertificate() {
		return acceptUntrustedCertificate;
	}

	public void setAcceptUntrustedCertificate(boolean acceptUntrustedCertificate) {
		this.acceptUntrustedCertificate = acceptUntrustedCertificate;
	}
}