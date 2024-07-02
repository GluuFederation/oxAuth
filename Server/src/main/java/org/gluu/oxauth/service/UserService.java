/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.fido.u2f.DeviceRegistration;
import org.gluu.oxauth.model.fido.u2f.DeviceRegistrationStatus;
import org.gluu.persist.model.base.CustomEntry;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.persist.model.fido2.Fido2RegistrationEntry;
import org.gluu.search.filter.Filter;
import org.gluu.service.net.NetworkService;
import org.gluu.util.StringHelper;

/**
 * Provides operations with users.
 *
 * @author Javier Rojas Blum
 * @version @version August 20, 2019
 */
@ApplicationScoped
public class UserService extends org.gluu.oxauth.service.common.UserService {

	public static final String[] USER_OBJECT_CLASSES = new String[] { "gluuPerson" };

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private AppConfiguration appConfiguration;
    
    @Inject
    private NetworkService networkService;

    @Override
	protected List<String> getPersonCustomObjectClassList() {
		return appConfiguration.getPersonCustomObjectClassList();
	}

    @Override
	protected String getPeopleBaseDn() {
		return staticConfiguration.getBaseDn().getPeople();
	}


    public long countFido2RegisteredDevices(String username, String domain) {
        String userInum = getUserInum(username);
        if (userInum == null) {
            return 0;
        }

        String baseDn = getBaseDnForFido2RegistrationEntries(userInum);
        if (persistenceEntryManager.hasBranchesSupport(baseDn)) {
            if (!persistenceEntryManager.contains(baseDn, SimpleBranch.class)) {
                return 0;
            }
        }

        Filter userInumFilter = Filter.createEqualityFilter("personInum", userInum);
        Filter registeredFilter = Filter.createEqualityFilter("oxStatus", "registered");
        Filter domainFilter = Filter.createEqualityFilter("oxApplication", domain);
        Filter filter = Filter.createANDFilter(userInumFilter, registeredFilter, domainFilter);

        return persistenceEntryManager.countEntries(baseDn, Fido2RegistrationEntry.class, filter);
    }

    public String getBaseDnForFido2RegistrationEntries(String userInum) {
        final String userBaseDn = getDnForUser(userInum); // "ou=fido2_register,inum=1234,ou=people,o=gluu"

        return String.format("ou=fido2_register,%s", userBaseDn);
    }

    public String getBaseDnForFidoDevices(String userInum) {
        final String userBaseDn = getDnForUser(userInum); // "ou=fido,inum=1234,ou=people,o=gluu"

        return String.format("ou=fido,%s", userBaseDn);
	}

}
