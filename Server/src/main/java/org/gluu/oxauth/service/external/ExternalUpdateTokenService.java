/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2021, Gluu
 */

package org.gluu.oxauth.service.external;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.token.UpdateTokenType;
import org.gluu.oxauth.model.common.AccessToken;
import org.gluu.oxauth.model.common.RefreshToken;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.service.external.context.ExternalUpdateTokenContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import java.util.List;

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

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }

        return false;
    }

    public boolean modifyIdTokenMethods(JsonWebResponse jsonWebResponse, ExternalUpdateTokenContext context) {
        for (CustomScriptConfiguration script : getScripts()) {
            if (!modifyIdTokenMethod(script, jsonWebResponse, context)) {
                return false;
            }
        }

        return true;
    }

    @NotNull
    private List<CustomScriptConfiguration> getScripts() {
        if (customScriptConfigurations == null) {
            return Lists.newArrayList();
        }

        return customScriptConfigurations;
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

    public boolean modifyRefreshToken(CustomScriptConfiguration script, RefreshToken refreshToken, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'modifyRefreshToken' method, script name: {}, context: {}", script.getName(), context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final boolean result = updateTokenType.modifyRefreshToken(refreshToken, context);
            log.trace("Finished 'modifyRefreshToken' method, script name: {}, context: {}, result: {}", script.getName(), context, result);

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }

        return false;
    }

    public boolean modifyRefreshToken(RefreshToken refreshToken, ExternalUpdateTokenContext context) {
        List<CustomScriptConfiguration> scripts = getScripts();
        if (scripts.isEmpty()) {
            return true;
        }
        log.trace("Executing {} update-token modifyRefreshToken scripts.", scripts.size());

        for (CustomScriptConfiguration script : scripts) {
            if (!modifyRefreshToken(script, refreshToken, context)) {
                return false;
            }
        }

        return true;
    }

    public boolean modifyAccessToken(CustomScriptConfiguration script, AccessToken accessToken, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'modifyAccessToken' method, script name: {}, context: {}", script.getName(), context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final boolean result = updateTokenType.modifyAccessToken(accessToken, context);
            log.trace("Finished 'modifyAccessToken' method, script name: {}, context: {}, result: {}", script.getName(), context, result);

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }

        return false;
    }

    public boolean modifyAccessToken(AccessToken accessToken, ExternalUpdateTokenContext context) {
        List<CustomScriptConfiguration> scripts = getScripts();
        if (scripts.isEmpty()) {
            return true;
        }
        log.trace("Executing {} update-token modifyAccessToken scripts.", scripts.size());

        for (CustomScriptConfiguration script : scripts) {
            if (!modifyAccessToken(script, accessToken, context)) {
                return false;
            }
        }

        return true;
    }

    public int getAccessTokenLifetimeInSeconds(CustomScriptConfiguration script, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'getAccessTokenLifetimeInSeconds' method, script name: {}, context: {}", script.getName(), context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final int result = updateTokenType.getAccessTokenLifetimeInSeconds(context);
            log.trace("Finished 'getAccessTokenLifetimeInSeconds' method, script name: {}, context: {}, result: {}", script.getName(), context, result);

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }
        return 0;
    }

    public int getAccessTokenLifetimeInSeconds(ExternalUpdateTokenContext context) {
        List<CustomScriptConfiguration> scripts = getScripts();
        if (scripts.isEmpty()) {
            return 0;
        }
        log.trace("Executing {} 'getAccessTokenLifetimeInSeconds' scripts.", scripts.size());

        for (CustomScriptConfiguration script : scripts) {
            final int lifetime = getAccessTokenLifetimeInSeconds(script, context);
            if (lifetime > 0) {
                log.trace("Finished 'getAccessTokenLifetimeInSeconds' methods, lifetime: {}", lifetime);
                return lifetime;
            }
        }
        return 0;
    }

    public int getIdTokenLifetimeInSeconds(CustomScriptConfiguration script, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'getIdTokenLifetimeInSeconds' method, script name: {}, context: {}", script.getName(), context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final int result = updateTokenType.getIdTokenLifetimeInSeconds(context);
            log.trace("Finished 'getIdTokenLifetimeInSeconds' method, script name: {}, context: {}, result: {}", script.getName(), context, result);

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }
        return 0;
    }

    public int getIdTokenLifetimeInSeconds(ExternalUpdateTokenContext context) {
        List<CustomScriptConfiguration> scripts = getScripts();
        if (scripts.isEmpty()) {
            return 0;
        }
        log.trace("Executing {} 'getIdTokenLifetimeInSeconds' scripts.", scripts.size());

        for (CustomScriptConfiguration script : scripts) {
            final int lifetime = getIdTokenLifetimeInSeconds(script, context);
            if (lifetime > 0) {
                log.trace("Finished 'getIdTokenLifetimeInSeconds' methods, lifetime: {}", lifetime);
                return lifetime;
            }
        }
        return 0;
    }

    public int getRefreshTokenLifetimeInSeconds(CustomScriptConfiguration script, ExternalUpdateTokenContext context) {
        try {
            log.trace("Executing python 'getRefreshTokenLifetimeInSeconds' method, script name: {}, context: {}", script.getName(), context);
            context.setScript(script);

            UpdateTokenType updateTokenType = (UpdateTokenType) script.getExternalType();
            final int result = updateTokenType.getRefreshTokenLifetimeInSeconds(context);
            log.trace("Finished 'getRefreshTokenLifetimeInSeconds' method, script name: {}, context: {}, result: {}", script.getName(), context, result);

            context.throwWebApplicationExceptionIfSet();
            return result;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }
        return 0;
    }

    public int getRefreshTokenLifetimeInSeconds(ExternalUpdateTokenContext context) {
        List<CustomScriptConfiguration> scripts = getScripts();
        if (scripts.isEmpty()) {
            return 0;
        }
        log.trace("Executing {} 'getRefreshTokenLifetimeInSeconds' scripts.", scripts.size());

        for (CustomScriptConfiguration script : scripts) {
            final int lifetime = getRefreshTokenLifetimeInSeconds(script, context);
            if (lifetime > 0) {
                log.trace("Finished 'getRefreshTokenLifetimeInSeconds' methods, lifetime: {}", lifetime);
                return lifetime;
            }
        }
        return 0;
    }
}
