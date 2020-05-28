/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.ciba;

import org.gluu.oxauth.interception.CIBASupportInterception;
import org.gluu.oxauth.interception.CIBASupportInterceptionInterface;

import javax.ejb.Stateless;
import javax.inject.Named;

/**
 * @author Javier Rojas Blum
 * @version August 20, 2019
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