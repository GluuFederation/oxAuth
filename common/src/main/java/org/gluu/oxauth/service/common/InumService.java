/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.common;

import java.util.UUID;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.oxauth.model.util.Pair;
import org.slf4j.Logger;

/**
 * Provides operations with clients.
 *
 * @author Javier Rojas Date: 01.12.2012
 */
@ApplicationScoped
public class InumService {

    @Inject
    private Logger log;

    public String generateClientInum() {
        return UUID.randomUUID().toString();
    }

    public String generatePeopleInum() {
        return UUID.randomUUID().toString();
    }

    public String generateInum() {
        return generateClientInum();
    }

    public Pair<String, String> generateNewDN(String baseDn) {
        final String inum = generateInum();
        final StringBuilder dnSb = new StringBuilder("inum=");
        dnSb.append(inum).append(",").append(baseDn);
        final String dn = dnSb.toString();
        log.trace("Generated dn: {}", dn);
        return new Pair<>(inum, dn);
    }

}