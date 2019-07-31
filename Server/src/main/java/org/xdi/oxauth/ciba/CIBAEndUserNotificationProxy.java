/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.xdi.oxauth.interception.CIBAEndUserNotificationInterception;
import org.xdi.oxauth.interception.CIBAEndUserNotificationInterceptionInterface;

import javax.ejb.Stateless;
import javax.inject.Named;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
@Stateless
@Named
public class CIBAEndUserNotificationProxy implements CIBAEndUserNotificationInterceptionInterface {

    @Override
    @CIBAEndUserNotificationInterception
    public void notifyEndUser(String authorizationRequestId, String deviceRegistrationToken) {
    }
}
