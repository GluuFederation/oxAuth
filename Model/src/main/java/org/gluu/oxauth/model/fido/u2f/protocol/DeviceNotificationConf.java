/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */

package org.gluu.oxauth.model.fido.u2f.protocol;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * FIDO2 U2F device notification configuration
 *
 * @author Yuriy Movchan Date: 03/21/2024
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class DeviceNotificationConf implements Serializable {

	private static final long serialVersionUID = -8173244116167488365L;

	@JsonProperty(value = "sns_endpoint_arn")
	private String snsEndpointArn;

	@JsonProperty(value = "sns_endpoint_arn_remove")
	private String snsEndpointArnRemove;

    @JsonProperty(value = "sns_endpoint_arn_history")
    private List<String> snsEndpointArnHistory;

	public DeviceNotificationConf(@JsonProperty(value = "sns_endpoint_arn") String snsEndpointArn, @JsonProperty(value = "sns_endpoint_arn_remove") String snsEndpointArnRemove,
			@JsonProperty(value = "sns_endpoint_arn_history") List<String> snsEndpointArnHistory) {
		this.snsEndpointArn = snsEndpointArn;
		this.snsEndpointArnRemove = snsEndpointArnRemove;
		this.snsEndpointArnHistory = snsEndpointArnHistory;
	}

	public String getSnsEndpointArn() {
		return snsEndpointArn;
	}

	public void setSnsEndpointArn(String snsEndpointArn) {
		this.snsEndpointArn = snsEndpointArn;
	}

	public String getSnsEndpointArnRemove() {
		return snsEndpointArnRemove;
	}

	public void setSnsEndpointArnRemove(String snsEndpointArnRemove) {
		this.snsEndpointArnRemove = snsEndpointArnRemove;
	}

	public List<String> getSnsEndpointArnHistory() {
		return snsEndpointArnHistory;
	}

	public void setSnsEndpointArnHistory(List<String> snsEndpointArnHistory) {
		this.snsEndpointArnHistory = snsEndpointArnHistory;
	}

	@Override
	public String toString() {
		return "Fido2DeviceNotificationConf [snsEndpointArn=" + snsEndpointArn + ", snsEndpointArnRemove="
				+ snsEndpointArnRemove + ", snsEndpointArnHistory=" + snsEndpointArnHistory + "]";
	}

}
