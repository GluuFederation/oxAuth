/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2021, Gluu
 */

package org.gluu.oxauth.service.external;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.token.UpdateTokenType;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.service.external.context.ExternalUpdateTokenContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.slf4j.Logger;

import com.google.common.base.Function;

/**
 * @author Yuriy Movchan
 */
@ApplicationScoped
public class ExternalUpdateTokenService extends ExternalScriptService {

	private static final long serialVersionUID = -1033475075863270249L;

	@Inject
    private Logger log;

    public ExternalUpdateTokenService() {
        super(CustomScriptType.UPDATE_TOKEN);
    }

    public boolean modifyIdTokenMethod(CustomScriptConfiguration script, JsonWebResponse jsonWebResponse, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'updateToken' method, script name: {}, jsonWebResponse: {}, context: {}", script.getName(), jsonWebResponse, context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final boolean result = updateTokenType.modifyIdToken(jsonWebResponse, context);
            log.trace("Finished 'updateToken' method, script name: {}, jsonWebResponse: {}, context: {}, result: {}", script.getName(), jsonWebResponse, context, result);

            return result;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }

        return false;
    }

    public boolean modifyIdTokenMethods(JsonWebResponse jsonWebResponse, ExternalUpdateTokenContext context) {
        if (this.customScriptConfigurations.isEmpty()) {
            return false;
        }
        log.trace("Executing {} update-token scripts.", this.customScriptConfigurations.size());

        for (CustomScriptConfiguration script : this.customScriptConfigurations) {
            if (!modifyIdTokenMethod(script, jsonWebResponse, context)) {
                return false;
            }
        }

        return true;
    }
    
	public Function<JsonWebResponse, Void> buildModifyIdTokenProcessor(final ExternalUpdateTokenContext context) {
		return new Function<JsonWebResponse, Void>() {
			@Override
			public Void apply(JsonWebResponse jsonWebResponse) {
				modifyIdTokenMethods(jsonWebResponse, context);

				return null;
			}
		};
	}

}
