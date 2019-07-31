/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.interception;

import org.xdi.oxauth.model.error.DefaultErrorResponse;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
public interface CIBADeviceRegistrationValidatorInterceptionInterface {

    DefaultErrorResponse validateParams(String deviceRegistrationToken);
}
