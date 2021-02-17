package org.gluu.oxauth.service.external.context;

import javax.servlet.http.HttpServletRequest;

import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.model.common.AuthorizationGrant;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.service.AttributeService;

/**
 * @author Yuriy Movchan
 */
public class ExternalUpdateTokenContext extends ExternalScriptContext {

	private final Client client;
	private final AuthorizationGrant grant;

	private CustomScriptConfiguration script;

	private final AppConfiguration appConfiguration;
	private final AttributeService attributeService;

	public ExternalUpdateTokenContext(HttpServletRequest httpRequest, AuthorizationGrant grant,
			Client client, AppConfiguration appConfiguration, AttributeService attributeService) {
		super(httpRequest);
		this.client = client;
		this.grant = grant;
		this.script = script;
		this.appConfiguration = appConfiguration;
		this.attributeService = attributeService;
	}

	public CustomScriptConfiguration getScript() {
		return script;
	}

	public void setScript(CustomScriptConfiguration script) {
		this.script = script;
	}

	public Client getClient() {
		return client;
	}

	public AuthorizationGrant getGrant() {
		return grant;
	}

	public AppConfiguration getAppConfiguration() {
		return appConfiguration;
	}

	public AttributeService getAttributeService() {
		return attributeService;
	}

}
