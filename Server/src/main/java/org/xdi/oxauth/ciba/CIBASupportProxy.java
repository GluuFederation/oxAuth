/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.xdi.oxauth.interception.CIBASupportInterception;
import org.xdi.oxauth.interception.CIBASupportInterceptionInterface;

import javax.ejb.Stateless;
import javax.inject.Named;

/**
 * @author Javier Rojas Blum
 * @version March 25, 2019
 */
@Stateless
@Named
public class CIBASupportProxy implements CIBASupportInterceptionInterface {

    @Override
    @CIBASupportInterception
    public boolean isCIBASupported() {
        return false;
    }
}
