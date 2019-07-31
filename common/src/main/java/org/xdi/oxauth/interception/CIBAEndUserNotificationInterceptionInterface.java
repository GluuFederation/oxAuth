/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.interception;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
public interface CIBAEndUserNotificationInterceptionInterface {

    void notifyEndUser(String authorizationRequestId, String deviceRegistrationToken);
}
