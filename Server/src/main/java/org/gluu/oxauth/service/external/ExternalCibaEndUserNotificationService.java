package org.gluu.oxauth.service.external;

import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.ciba.EndUserNotificationType;
import org.gluu.oxauth.service.external.context.ExternalCibaEndUserNotificationContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.slf4j.Logger;

import javax.ejb.DependsOn;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;

/**
 * @author Milton BO
 */
@ApplicationScoped
@DependsOn("appInitializer")
@Named
public class ExternalCibaEndUserNotificationService extends ExternalScriptService {

    private static final long serialVersionUID = -8609727759114795446L;

    @Inject
    private Logger log;

    public ExternalCibaEndUserNotificationService() {
        super(CustomScriptType.CIBA_END_USER_NOTIFICATION);
    }

    public boolean executeExternalNotifyEndUser(ExternalCibaEndUserNotificationContext context) {
        if (customScriptConfigurations == null || customScriptConfigurations.isEmpty()) {
            log.trace("There is no any external interception scripts defined.");
            return false;
        }

        for (CustomScriptConfiguration script : customScriptConfigurations) {
            if (!executeExternalNotifyEndUser(script, context)) {
                log.trace("Stopped running external interception scripts because script {} returns false.", script.getName());
                return false;
            }
        }
        return true;
    }

    private boolean executeExternalNotifyEndUser(CustomScriptConfiguration customScriptConfiguration,
                                                 ExternalCibaEndUserNotificationContext context) {
        try {
            log.trace("Executing external 'executeExternalNotifyEndUser' method, script name: {}, context: {}",
                    customScriptConfiguration.getName(), context);

            EndUserNotificationType script = (EndUserNotificationType) customScriptConfiguration.getExternalType();
            final boolean result = script.notifyEndUser(context);
            log.trace("Finished external 'executeExternalNotifyEndUser' method, script name: {}, context: {}, result: {}",
                    customScriptConfiguration.getName(), context, result);
            return result;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(customScriptConfiguration.getCustomScript(), ex);
            return false;
        }
    }
}
