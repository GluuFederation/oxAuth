/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */

package org.gluu.oxauth.model.fido.u2f;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.jboss.resteasy.annotations.providers.jaxb.IgnoreMediaTypes;

/**
 * FIDO U2F metadata configuration
 *
 * @author Yuriy Movchan Date: 05/13/2015
 */
@IgnoreMediaTypes("application/*+json")
@JsonPropertyOrder({ "version", "issuer", "registration_endpoint", "authentication_endpoint" })
public class U2fConfiguration {

	@JsonProperty(value = "version")
	private String version;

	@JsonProperty(value = "issuer")
	private String issuer;

	@JsonProperty(value = "registration_endpoint")
	private String registrationEndpoint;

	@JsonProperty(value = "authentication_endpoint")
	private String authenticationEndpoint;

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getRegistrationEndpoint() {
		return registrationEndpoint;
	}

	public void setRegistrationEndpoint(String registrationEndpoint) {
		this.registrationEndpoint = registrationEndpoint;
	}

	public String getAuthenticationEndpoint() {
		return authenticationEndpoint;
	}

	public void setAuthenticationEndpoint(String authenticationEndpoint) {
		this.authenticationEndpoint = authenticationEndpoint;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("U2fConfiguration [version=").append(version).append(", issuer=").append(issuer).append(", registrationEndpoint=")
				.append(registrationEndpoint).append(", authenticationEndpoint=").append(authenticationEndpoint).append("]");
		return builder.toString();
	}


}
