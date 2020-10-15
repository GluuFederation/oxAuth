/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.external;

import org.gluu.model.SimpleCustomProperty;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.client.ClientRegistrationType;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.service.external.context.DynamicClientRegistrationContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.json.JSONObject;

import javax.ejb.DependsOn;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Provides factory methods needed to create external dynamic client registration extension
 *
 * @author Yuriy Movchan Date: 01/08/2015
 */
@ApplicationScoped
@DependsOn("appInitializer")
@Named
public class ExternalDynamicClientRegistrationService extends ExternalScriptService {

	private static final long serialVersionUID = 1416361273036208686L;

	public ExternalDynamicClientRegistrationService() {
		super(CustomScriptType.CLIENT_REGISTRATION);
	}

    public boolean executeExternalCreateClientMethod(CustomScriptConfiguration customScriptConfiguration, RegisterRequest registerRequest, Client client) {
        try {
            log.trace("Executing python 'createClient' method");
            ClientRegistrationType externalClientRegistrationType = (ClientRegistrationType) customScriptConfiguration.getExternalType();
            Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
            return externalClientRegistrationType.createClient(registerRequest, client, configurationAttributes);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
        }
        
        return false;
    }

    public boolean executeExternalCreateClientMethods(RegisterRequest registerRequest, Client client) {
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            if (customScriptConfiguration.getExternalType().getApiVersion() > 1) {
                result &= executeExternalCreateClientMethod(customScriptConfiguration, registerRequest, client);
                if (!result) {
                    return result;
                }
            }
        }

        return result;
    }

	public boolean executeExternalUpdateClientMethod(CustomScriptConfiguration customScriptConfiguration, RegisterRequest registerRequest, Client client) {
		try {
			log.trace("Executing python 'updateClient' method");
			ClientRegistrationType externalClientRegistrationType = (ClientRegistrationType) customScriptConfiguration.getExternalType();
			Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
			return externalClientRegistrationType.updateClient(registerRequest, client, configurationAttributes);
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
		}
		
		return false;
	}

	public boolean executeExternalUpdateClientMethods(RegisterRequest registerRequest, Client client) {
		boolean result = true;
		for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
			result &= executeExternalUpdateClientMethod(customScriptConfiguration, registerRequest, client);
			if (!result) {
				return result;
			}
		}

		return result;
	}

    public JSONObject getSoftwareStatementJwks(HttpServletRequest httpRequest, JSONObject registerRequest, Jwt softwareStatement) {
        try {
            log.trace("Executing python 'getSoftwareStatementJwks' method");

            DynamicClientRegistrationContext context = new DynamicClientRegistrationContext(httpRequest, registerRequest, defaultExternalCustomScript);
            context.setSoftwareStatement(softwareStatement);

            ClientRegistrationType externalType = (ClientRegistrationType) defaultExternalCustomScript.getExternalType();
            final String result = externalType.getSoftwareStatementJwks(context);
            log.trace("Result of python 'getSoftwareStatementJwks' method: " + result);
            return new JSONObject(result);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(defaultExternalCustomScript.getCustomScript(), ex);
            return null;
        }
    }

    public String getSoftwareStatementHmacSecret(HttpServletRequest httpRequest, JSONObject registerRequest, Jwt softwareStatement) {
        try {
            log.trace("Executing python 'getSoftwareStatementHmacSecret' method");

            DynamicClientRegistrationContext context = new DynamicClientRegistrationContext(httpRequest, registerRequest, defaultExternalCustomScript);
            context.setSoftwareStatement(softwareStatement);

            ClientRegistrationType externalType = (ClientRegistrationType) defaultExternalCustomScript.getExternalType();
            final String result = externalType.getSoftwareStatementHmacSecret(context);
            log.trace("Result of python 'getSoftwareStatementHmacSecret' method: " + result);
            return result;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(defaultExternalCustomScript.getCustomScript(), ex);
            return "";
        }
    }
}
