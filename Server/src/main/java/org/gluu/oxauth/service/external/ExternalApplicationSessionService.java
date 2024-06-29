/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.external;

import org.gluu.model.SimpleCustomProperty;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.session.ApplicationSessionType;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.service.external.session.SessionEvent;
import org.gluu.service.custom.script.ExternalScriptService;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Provides factory methods needed to create external application session extension
 *
 * @author Yuriy Movchan
 * @version August 9, 2017
 */
@ApplicationScoped
public class ExternalApplicationSessionService extends ExternalScriptService {

    private static final long serialVersionUID = 2316361273036208685L;

    public ExternalApplicationSessionService() {
        super(CustomScriptType.APPLICATION_SESSION);
    }

    public boolean executeExternalStartSessionMethod(CustomScriptConfiguration customScriptConfiguration, HttpServletRequest httpRequest, SessionId sessionId) {
        try {
            log.trace("Executing python 'startSession' method");
            ApplicationSessionType applicationSessionType = (ApplicationSessionType) customScriptConfiguration.getExternalType();
            Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
            return applicationSessionType.startSession(httpRequest, sessionId, configurationAttributes);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
        }

        return false;
    }

    public boolean executeExternalStartSessionMethods(HttpServletRequest httpRequest, SessionId sessionId) {
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            if (customScriptConfiguration.getExternalType().getApiVersion() > 1) {
                result &= executeExternalStartSessionMethod(customScriptConfiguration, httpRequest, sessionId);
                if (!result) {
                    return result;
                }
            }
        }

        return result;
    }

    public boolean executeExternalEndSessionMethod(CustomScriptConfiguration customScriptConfiguration, HttpServletRequest httpRequest, SessionId sessionId) {
        try {
            log.trace("Executing python 'endSession' method");
            ApplicationSessionType applicationSessionType = (ApplicationSessionType) customScriptConfiguration.getExternalType();
            Map<String, SimpleCustomProperty> configurationAttributes = customScriptConfiguration.getConfigurationAttributes();
            return applicationSessionType.endSession(httpRequest, sessionId, configurationAttributes);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
        }

        return false;
    }

    public boolean executeExternalEndSessionMethods(HttpServletRequest httpRequest, SessionId sessionId) {
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            result &= executeExternalEndSessionMethod(customScriptConfiguration, httpRequest, sessionId);
            if (!result) {
                return result;
            }
        }

        return result;
    }

    public void externalEvent(SessionEvent event) {
        if (!isEnabled()) {
            return;
        }

        for (CustomScriptConfiguration scriptConfiguration : this.customScriptConfigurations) {
            externalEvent(scriptConfiguration, event);
        }
    }

    private void externalEvent(CustomScriptConfiguration scriptConfiguration, SessionEvent event) {
        try {
            log.trace("Executing python 'onEvent' method of script: " + scriptConfiguration.getName() + ", event: " + event);
            event.setScriptConfiguration(scriptConfiguration);
            ApplicationSessionType applicationSessionType = (ApplicationSessionType) scriptConfiguration.getExternalType();
            applicationSessionType.onEvent(event);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(scriptConfiguration.getCustomScript(), ex);
        }
    }

}
