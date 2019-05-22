/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.xdi.oxauth.interception.CIBAAuthorizeParamsValidatorInterception;
import org.xdi.oxauth.interception.CIBAAuthorizeParamsValidatorInterceptionInterface;
import org.xdi.oxauth.model.common.BackchannelTokenDeliveryMode;
import org.xdi.oxauth.model.error.DefaultErrorResponse;

import javax.ejb.Stateless;
import javax.inject.Named;
import java.util.List;

/**
 * @author Javier Rojas Blum
 * @version May 22, 2019
 */
@Stateless
@Named
public class CIBAAuthorizeParamsValidatorProxy implements CIBAAuthorizeParamsValidatorInterceptionInterface {

    @Override
    @CIBAAuthorizeParamsValidatorInterception
    public DefaultErrorResponse validateParams(
            List<String> scopeList, String clientNotificationToken, BackchannelTokenDeliveryMode tokenDeliveryMode,
            String loginHintToken, String idTokenHint, String loginHint, String bindingMessage,
            Boolean backchannelUserCodeParameter, String userCode) {
        return null;
    }
}
