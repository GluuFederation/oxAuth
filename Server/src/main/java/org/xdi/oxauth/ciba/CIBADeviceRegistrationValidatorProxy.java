/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.xdi.oxauth.interception.CIBADeviceRegistationValidatorInterception;
import org.xdi.oxauth.interception.CIBADeviceRegistrationValidatorInterceptionInterface;
import org.xdi.oxauth.model.error.DefaultErrorResponse;

import javax.ejb.Stateless;
import javax.inject.Named;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
@Stateless
@Named
public class CIBADeviceRegistrationValidatorProxy implements CIBADeviceRegistrationValidatorInterceptionInterface {

    @Override
    @CIBADeviceRegistationValidatorInterception
    public DefaultErrorResponse validateParams(String deviceRegistrationToken) {
        return null;
    }
}
