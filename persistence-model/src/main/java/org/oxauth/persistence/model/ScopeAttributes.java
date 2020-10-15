package org.oxauth.persistence.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

/**
 * @author Yuriy Zabrovarnyy
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScopeAttributes implements Serializable {

	private static final long serialVersionUID = 213428216911083393L;

	@JsonProperty("spontaneousClientId")
	private String spontaneousClientId;

	@JsonProperty("spontaneousClientScopes")
	private List<String> spontaneousClientScopes;

	@JsonProperty("showInConfigurationEndpoint")
	private boolean showInConfigurationEndpoint = true;

	public String getSpontaneousClientId() {
		return spontaneousClientId;
	}

	public void setSpontaneousClientId(String spontaneousClientId) {
		this.spontaneousClientId = spontaneousClientId;
	}

	public List<String> getSpontaneousClientScopes() {
		return spontaneousClientScopes;
	}

	public void setSpontaneousClientScopes(List<String> spontaneousClientScopes) {
		this.spontaneousClientScopes = spontaneousClientScopes;
	}

	public boolean isShowInConfigurationEndpoint() {
		return showInConfigurationEndpoint;
	}

	public void setShowInConfigurationEndpoint(boolean showInConfigurationEndpoint) {
		this.showInConfigurationEndpoint = showInConfigurationEndpoint;
	}

	@Override
	public String toString() {
		return "ScopeAttributes{" + "spontaneousClientId='" + spontaneousClientId + '\'' + "spontaneousClientScopes='"
				+ spontaneousClientScopes + '\'' + "showInConfigurationEndpoint='" + showInConfigurationEndpoint + '\''
				+ '}';
	}
}
