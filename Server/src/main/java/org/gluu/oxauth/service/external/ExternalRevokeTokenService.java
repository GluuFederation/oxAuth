package org.gluu.oxauth.service.external;

import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.revoke.RevokeTokenType;
import org.gluu.oxauth.service.external.context.RevokeTokenContext;
import org.gluu.service.custom.script.ExternalScriptService;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class ExternalRevokeTokenService extends ExternalScriptService {

    @Inject
    private Logger log;

    public ExternalRevokeTokenService() {
        super(CustomScriptType.REVOKE_TOKEN);
    }

    public boolean revokeToken(CustomScriptConfiguration script, RevokeTokenContext context) {
        try {
            log.trace("Executing python 'revokeToken' method, context: {}", context);
            context.setScript(script);
            RevokeTokenType revokeTokenType = (RevokeTokenType) script.getExternalType();
            final boolean result = revokeTokenType.revoke(context);
            log.trace("Finished 'revokeToken' method, result: {}, context: {}", result, context);
            return result;
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            saveScriptError(script.getCustomScript(), ex);
        }

        return false;
    }

    public boolean revokeTokenMethods(RevokeTokenContext context) {
        for (CustomScriptConfiguration script : this.customScriptConfigurations) {
            if (script.getExternalType().getApiVersion() > 1) {
                if (!revokeToken(script, context)) {
                    return false;
                }
            }
        }
        return true;
    }
}
