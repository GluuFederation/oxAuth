package org.gluu.oxauth.service.external;

import org.codehaus.jettison.json.JSONObject;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.introspection.IntrospectionType;
import org.gluu.oxauth.service.external.context.ExternalIntrospectionContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.slf4j.Logger;

import javax.ejb.DependsOn;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
@DependsOn("appInitializer")
@Named
public class ExternalIntrospectionService extends ExternalScriptService {

    private static final long serialVersionUID = -8609727759114795446L;

    @Inject
    private Logger log;

    public ExternalIntrospectionService() {
        super(CustomScriptType.INTROSPECTION);
    }

    public boolean executeExternalModifyResponse(JSONObject responseAsJsonObject, ExternalIntrospectionContext context) {
        if (customScriptConfigurations == null || customScriptConfigurations.isEmpty()) {
            log.debug("There is no any external interception scripts defined.");
            return false;
        }

        for (CustomScriptConfiguration script : customScriptConfigurations) {
            if (!executeExternalModifyResponse(script, responseAsJsonObject, context)) {
                log.debug("Stopped running external interception scripts because script {} returns false.", script.getName());
                return false;
            }
        }

        return true;
    }

    private boolean executeExternalModifyResponse(CustomScriptConfiguration customScriptConfiguration, JSONObject responseAsJsonObject, ExternalIntrospectionContext context) {
        try {
            log.debug("Executing external 'executeExternalModifyResponse' method, script name: {}, responseAsJsonObject: {} , context: {}",
                    customScriptConfiguration.getName(), responseAsJsonObject, context);

            IntrospectionType script = (IntrospectionType) customScriptConfiguration.getExternalType();
            context.setScript(customScriptConfiguration);
            final boolean result = script.modifyResponse(responseAsJsonObject, context);
            log.debug("Finished external 'executeExternalModifyResponse' method, script name: {}, responseAsJsonObject: {} , context: {}, result: {}",
                    customScriptConfiguration.getName(), responseAsJsonObject, context, result);
            return result;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
            return false;
        }
    }
}
