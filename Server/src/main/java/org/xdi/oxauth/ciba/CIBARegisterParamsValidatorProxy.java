/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.xdi.oxauth.interception.CIBARegisterParamsValidatorInterception;
import org.xdi.oxauth.interception.CIBARegisterParamsValidatorInterceptionInterface;
import org.xdi.oxauth.model.common.BackchannelTokenDeliveryMode;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.crypto.signature.AsymmetricSignatureAlgorithm;

import javax.ejb.Stateless;
import javax.inject.Named;
import java.util.List;

/**
 * @author Javier Rojas Blum
 * @version March 25, 2019
 */
@Stateless
@Named
public class CIBARegisterParamsValidatorProxy implements CIBARegisterParamsValidatorInterceptionInterface {

    @Override
    @CIBARegisterParamsValidatorInterception
    public boolean validateParams(
            BackchannelTokenDeliveryMode backchannelTokenDeliveryMode, String backchannelClientNotificationEndpoint,
            AsymmetricSignatureAlgorithm backchannelAuthenticationRequestSigningAlg, Boolean backchannelUserCodeParameter,
            List<GrantType> grantTypes, SubjectType subjectType, String sectorIdentifierUri, String jwksUri) {
        return false;
    }
}
