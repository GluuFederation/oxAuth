package org.gluu.oxauth.service.common.fido2;

import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

import javax.inject.Inject;

import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.service.common.UserService;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.gluu.persist.model.fido2.Fido2RegistrationEntry;
import org.gluu.persist.model.fido2.Fido2RegistrationStatus;
import org.gluu.search.filter.Filter;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

/**
 * Abstract class for registrations that are persisted under Person Entry
 * @author madhumitas
 *
 */

public abstract class RegistrationPersistenceService {

	@Inject
	protected Logger log;

	@Inject
	protected PersistenceEntryManager persistenceEntryManager;

	@Inject
	protected UserService userService;

	@Inject
	protected StaticConfiguration staticConfiguration;
	
    public void save(Fido2RegistrationEntry registrationEntry) {
        prepareBranch(registrationEntry.getUserInum());

        persistenceEntryManager.persist(registrationEntry);
    }

    public void update(Fido2RegistrationEntry registrationEntry) {
        prepareBranch(registrationEntry.getUserInum());

        Date now = new GregorianCalendar(TimeZone.getTimeZone("UTC")).getTime();

        Fido2RegistrationData registrationData = registrationEntry.getRegistrationData();
        registrationData.setUpdatedDate(now);
        registrationData.setUpdatedBy(registrationData.getUsername());

        registrationEntry.setRegistrationStatus(registrationData.getStatus());

        persistenceEntryManager.merge(registrationEntry);
    }

    public void addBranch(final String baseDn) {
        SimpleBranch branch = new SimpleBranch();
        branch.setOrganizationalUnitName("fido2_register");
        branch.setDn(baseDn);

        persistenceEntryManager.persist(branch);
    }

    public boolean containsBranch(final String baseDn) {
        return persistenceEntryManager.contains(baseDn, SimpleBranch.class);
    }

    public String prepareBranch(final String userInum) {
        String baseDn = getBaseDnForFido2RegistrationEntries(userInum);
        if (!persistenceEntryManager.hasBranchesSupport(baseDn)) {
        	return baseDn;
        }

        // Create Fido2 base branch for registration entries if needed
        if (!containsBranch(baseDn)) {
            addBranch(baseDn);
        }
        
        return baseDn;
    }

    public Fido2RegistrationEntry findRegisteredUserDevice(String userInum, String deviceId, String... returnAttributes) {
        String baseDn = getBaseDnForFido2RegistrationEntries(userInum);
        if (persistenceEntryManager.hasBranchesSupport(baseDn)) {
        	if (!containsBranch(baseDn)) {
                return null;
        	}
        }

    	String deviceDn = getDnForRegistrationEntry(userInum, deviceId);

        return persistenceEntryManager.find(deviceDn, Fido2RegistrationEntry.class, returnAttributes);
    }

    public List<Fido2RegistrationEntry> findByRpRegisteredUserDevices(String userName, String rpId, String ... returnAttributes) {
		String userInum = userService.getUserInum(userName);
		if (userInum == null) {
			return Collections.emptyList();
		}

		String baseDn = getBaseDnForFido2RegistrationEntries(userInum);
        if (persistenceEntryManager.hasBranchesSupport(baseDn)) {
        	if (!containsBranch(baseDn)) {
                return Collections.emptyList();
        	}
        }

        Filter userInumFilter = Filter.createEqualityFilter("personInum", userInum);
        Filter registeredFilter = Filter.createEqualityFilter("jansStatus", Fido2RegistrationStatus.registered.getValue());
        Filter filter = null;
        if (StringHelper.isNotEmpty(rpId)) {
        	Filter appIdFilter = Filter.createEqualityFilter("oxApplication", rpId);
        	filter = Filter.createANDFilter(userInumFilter, registeredFilter, appIdFilter);
        }
        else
        {
        	filter = Filter.createANDFilter(userInumFilter, registeredFilter);
        }
        List<Fido2RegistrationEntry> fido2RegistrationnEntries = persistenceEntryManager.findEntries(baseDn, Fido2RegistrationEntry.class, filter, returnAttributes);

        return fido2RegistrationnEntries;
    }
    
    
    public boolean attachDeviceRegistrationToUser(String userInum, String deviceDn) {
		return attachDeviceRegistrationToUser(userInum, deviceDn, null);
    }

    public boolean attachDeviceRegistrationToUser(String userInum, String deviceDn, String deviceName) {
		Fido2RegistrationEntry registrationEntry = persistenceEntryManager.find(Fido2RegistrationEntry.class, deviceDn);
		if (registrationEntry == null) {
			return false;
		}

		User user = userService.getUserByInum(userInum, "uid");
		if (user == null) {
			return false;
		}

		persistenceEntryManager.remove(deviceDn, Fido2RegistrationEntry.class);

        final String id = UUID.randomUUID().toString();

        String userAttestationDn = getDnForRegistrationEntry(userInum, id);
        registrationEntry.setId(id);
        registrationEntry.setDn(userAttestationDn);
        registrationEntry.setUserInum(userInum);
        registrationEntry.setDisplayName(deviceName);

		Fido2RegistrationData registrationData = registrationEntry.getRegistrationData();
		registrationData.setUsername(user.getUserId());
		registrationEntry.clearExpiration();

		save(registrationEntry);

		return true;
    }

    public Fido2RegistrationEntry findOneStepUserDeviceRegistration(String deviceDn) {
		Fido2RegistrationEntry registrationEntry = persistenceEntryManager.find(Fido2RegistrationEntry.class, deviceDn);
		
		return registrationEntry;
    }

    public String getDnForRegistrationEntry(String userInum, String jsId) {
        // Build DN string for Fido2 registration entry
        String baseDn = getBaseDnForFido2RegistrationEntries(userInum);
        if (StringHelper.isEmpty(jsId)) {
            return baseDn;
        }
        return String.format("oxId=%s,%s", jsId, baseDn);
    }

    public String getBaseDnForFido2RegistrationEntries(String userInum) {
        final String userBaseDn = getDnForUser(userInum); // "ou=fido2_register,inum=1234,ou=people,o=jans"
        if (StringHelper.isEmpty(userInum)) {
            return userBaseDn;
        }

        return String.format("ou=fido2_register,%s", userBaseDn);
    }

    public String getDnForUser(String userInum) {
        String peopleDn = getBasedPeopleDn();
        if (StringHelper.isEmpty(userInum)) {
            return peopleDn;
        }

        return String.format("inum=%s,%s", userInum, peopleDn);
    }

    public String getBasedPeopleDn() {
    	return staticConfiguration.getBaseDn().getPeople();
    }
    
	public abstract String getUserInum(String userName);

}
