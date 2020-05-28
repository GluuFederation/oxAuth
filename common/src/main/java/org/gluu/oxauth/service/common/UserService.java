/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.common;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;
import javax.inject.Inject;

import org.gluu.model.GluuStatus;
import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.common.InumService;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.CustomAttribute;
import org.gluu.search.filter.Filter;
import org.gluu.util.ArrayHelper;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

/**
 * Provides operations with users.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version @version August 20, 2019
 */
public abstract class UserService {

	public static final String[] USER_OBJECT_CLASSES = new String[] { "gluuPerson" };

    @Inject
    private Logger log;

    @Inject
    protected PersistenceEntryManager persistenceEntryManager;

    @Inject
    private InumService inumService;

    /**
     * returns User by Dn
     *
     * @return User
     */
    @Nullable
    public User getUserByDn(String dn, String... returnAttributes) {
        if (Util.isNullOrEmpty(dn)) {
            return null;
        }
        return persistenceEntryManager.find(dn, User.class, returnAttributes);
    }

	public User getUserByInum(String inum, String... returnAttributes) {
		if (StringHelper.isEmpty(inum)) {
			return null;
		}
		
		String userDn = getDnForUser(inum);
		User user = getUserByDn(userDn, returnAttributes);
		if (user == null) {
			return null;
		}

		return user;
	}

	public User getUser(String userId, String... returnAttributes) {
		log.debug("Getting user information from LDAP: userId = {}", userId);

		if (StringHelper.isEmpty(userId)) {
			return null;
		}

		Filter userUidFilter = Filter.createEqualityFilter(Filter.createLowercaseFilter("uid"), StringHelper.toLowerCase(userId));

		List<User> entries = persistenceEntryManager.findEntries(getPeopleBaseDn(), User.class, userUidFilter, returnAttributes);
		log.debug("Found {} entries for user id = {}", entries.size(), userId);

		if (entries.size() > 0) {
			return entries.get(0);
		} else {
			return null;
		}
	}

	public String getUserInum(User user) {
		if (user == null) {
			return null;
		}
		
		String inum = user.getAttribute("inum");

		return inum;
	}

	public String getUserInum(String userId) {
		User user = getUser(userId, "inum");

		return getUserInum(user);
	}

    public User updateUser(User user) {
        user.setUpdatedAt(new Date());
		return persistenceEntryManager.merge(user);
	}

    public User addDefaultUser(String uid) {
        String peopleBaseDN = getPeopleBaseDn();

        String inum = inumService.generatePeopleInum();

    	User user = new User();
        user.setDn("inum=" + inum + "," + peopleBaseDN);
    	user.setCustomAttributes(Arrays.asList(
    			new CustomAttribute("inum", inum),
    			new CustomAttribute("gluuStatus", GluuStatus.ACTIVE.getValue()),
				new CustomAttribute("displayName", "User " + uid + " added via oxAuth custom plugin")));
    	user.setUserId(uid);

    	List<String> personCustomObjectClassList = getPersonCustomObjectClassList();
    	if ((personCustomObjectClassList != null) && !personCustomObjectClassList.isEmpty()) {
    		user.setCustomObjectClasses(personCustomObjectClassList.toArray(new String[personCustomObjectClassList.size()]));
    	}

    	user.setCreatedAt(new Date());
		persistenceEntryManager.persist(user);
		
		return getUser(uid);
	}

    public User addUser(User user, boolean active) {
        String peopleBaseDN = getPeopleBaseDn();

        String inum = inumService.generatePeopleInum();

        user.setDn("inum=" + inum + "," + peopleBaseDN);
        user.setAttribute("inum", inum);

        GluuStatus status = active ? GluuStatus.ACTIVE : GluuStatus.REGISTER;
        user.setAttribute("gluuStatus",  status.getValue());

        List<String> personCustomObjectClassList = getPersonCustomObjectClassList();
    	if ((personCustomObjectClassList != null) && !personCustomObjectClassList.isEmpty()) {
    		Set<String> allObjectClasses = new HashSet<>();
    		allObjectClasses.addAll(personCustomObjectClassList);

    		String currentObjectClasses[] = user.getCustomObjectClasses();
    		if (ArrayHelper.isNotEmpty(currentObjectClasses)) {
        		allObjectClasses.addAll(Arrays.asList(currentObjectClasses));
    		}

    		user.setCustomObjectClasses(allObjectClasses.toArray(new String[allObjectClasses.size()]));
    	}

    	user.setCreatedAt(new Date());
    	persistenceEntryManager.persist(user);

		return getUserByDn(user.getDn());
	}

    public User getUserByAttribute(String attributeName, String attributeValue) {
        log.debug("Getting user information from LDAP: attributeName = '{}', attributeValue = '{}'", attributeName, attributeValue);
        
        if (StringHelper.isEmpty(attributeName) || StringHelper.isEmpty(attributeValue)) {
        	return null;
        }

        User user = new User();
        user.setDn(getPeopleBaseDn());

        List<CustomAttribute> customAttributes =  new ArrayList<CustomAttribute>();
        customAttributes.add(new CustomAttribute(attributeName, attributeValue));

        user.setCustomAttributes(customAttributes);

        List<User> entries = persistenceEntryManager.findEntries(user, 1);
        log.debug("Found '{}' entries", entries.size());

        if (entries.size() > 0) {
            return entries.get(0);
        } else {
            return null;
        }
    }

	public User getUniqueUserByAttributes(List<String> attributeNames, String attributeValue) {
		log.debug("Getting user information from LDAP: attributeNames = '{}', attributeValue = '{}'", attributeNames, attributeValue);

		User user = null;

		if (attributeNames != null) {
			for (String attributeName : attributeNames) {
				User searchUser = new User();
				searchUser.setDn(getPeopleBaseDn());

				List<CustomAttribute> customAttributes =  new ArrayList<>();
				customAttributes.add(new CustomAttribute(attributeName, attributeValue));

				searchUser.setCustomAttributes(customAttributes);

				try {
					List<User> entries = persistenceEntryManager.findEntries(searchUser);
					log.debug("Found '{}' entries", entries.size());

					if (entries.size() == 0) {
						continue;
					} else if (entries.size() == 1) {
						user = entries.get(0);
						break;
					} else if (entries.size() > 0) {
						break;
					}
				} catch (Exception e) {
					log.debug(e.getMessage());
				}
			}
		}

		return user;
	}

	public User getUserByAttributes(String attributeValue, String[] attributeNames, String... returnAttributes) {
		if (ArrayHelper.isEmpty(attributeNames)) {
			return null;
		}

		log.debug("Getting user information from DB: {} = {}", ArrayHelper.toString(attributeNames), attributeValue);

		List<Filter> filters = new ArrayList<Filter>(); 
		for (String attributeName : attributeNames) {
			Filter filter = Filter.createEqualityFilter(Filter.createLowercaseFilter(attributeName), StringHelper.toLowerCase(attributeValue));
			filters.add(filter);
		}

		Filter searchFiler;
		if (filters.size() == 1) {
			searchFiler = filters.get(0);
		} else {
			searchFiler = Filter.createORFilter(filters);
		}

		List<User> entries = persistenceEntryManager.findEntries(getPeopleBaseDn(), User.class, searchFiler, returnAttributes);
		log.debug("Found {} entries for user {} = {}", entries.size(), ArrayHelper.toString(attributeNames), attributeValue);

		if (entries.size() > 0) {
			return entries.get(0);
		} else {
			return null;
		}
	}

    public List<User> getUsersBySample(User user, int limit) {
        log.debug("Getting user by sample");

        List<User> entries = persistenceEntryManager.findEntries(user, limit);
        log.debug("Found '{}' entries", entries.size());

        return entries;
    }

    public User addUserAttributeByUserInum(String userInum, String attributeName, String attributeValue) {
    	log.debug("Add user attribute by user inum  to LDAP: attributeName = '{}', attributeValue = '{}'", attributeName, attributeValue);

        User user = getUserByInum(userInum);
        if (user == null) {
        	return null;
        }
  
        boolean result = addUserAttribute(user, attributeName, attributeValue);
        if (!result) {
        	// We uses this result in Person Authentication Scripts
        	addUserAttribute(user, attributeName, attributeValue);
        }

        return updateUser(user);
    	
    }
    
    public User addUserAttribute(String userId, String attributeName, String attributeValue) {
        log.debug("Add user attribute to LDAP: attributeName = '{}', attributeValue = '{}'", attributeName, attributeValue);

        User user = getUser(userId);
        if (user == null) {
        	// We uses this result in Person Authentication Scripts
        	return null;
        }
        
        boolean result = addUserAttribute(user, attributeName, attributeValue);
        if (!result) {
        	// We uses this result in Person Authentication Scripts
        	return null;
        }

        return updateUser(user);
    }

    public boolean addUserAttribute(User user, String attributeName, String attributeValue) {
		CustomAttribute customAttribute = getCustomAttribute(user, attributeName);
        if (customAttribute == null) {
        	customAttribute = new CustomAttribute(attributeName, attributeValue);
            user.getCustomAttributes().add(customAttribute);
        } else {
        	List<String> currentAttributeValues = customAttribute.getValues();

        	List<String> newAttributeValues = new ArrayList<String>();
        	newAttributeValues.addAll(currentAttributeValues);

        	if (newAttributeValues.contains(attributeValue)) {
        		return false;
        	} else {
        		newAttributeValues.add(attributeValue);
        	}
        	
        	customAttribute.setValues(newAttributeValues);
        }
        
        return true;
	}

    public User removeUserAttribute(String userId, String attributeName, String attributeValue) {
        log.debug("Remove user attribute from LDAP: attributeName = '{}', attributeValue = '{}'", attributeName, attributeValue);

        User user = getUser(userId);
        if (user == null) {
        	return null;
        }
        
        CustomAttribute customAttribute = getCustomAttribute(user, attributeName);
        if (customAttribute != null) {
        	List<String> currentAttributeValues = customAttribute.getValues();
        	if (currentAttributeValues.contains(attributeValue)) {

        		List<String> newAttributeValues = new ArrayList<String>();
            	newAttributeValues.addAll(currentAttributeValues);
        		if (currentAttributeValues.contains(attributeValue)) {
            		newAttributeValues.remove(attributeValue);
            	} else {
            		return null;
            	}

        		customAttribute.setValues(newAttributeValues);
        	}
        }

		return updateUser(user);
    }

    public User replaceUserAttribute(String userId, String attributeName, String oldAttributeValue, String newAttributeValue) {
        log.debug("Replace user attribute in LDAP: attributeName = '{}', oldAttributeValue = '{}', newAttributeValue = '{}'", attributeName, oldAttributeValue, newAttributeValue);

        User user = getUser(userId);
        if (user == null) {
        	return null;
        }
        
        CustomAttribute customAttribute = getCustomAttribute(user, attributeName);
        if (customAttribute != null) {
        	List<String> currentAttributeValues = customAttribute.getValues();
    		List<String> newAttributeValues = new ArrayList<String>();
        	newAttributeValues.addAll(currentAttributeValues);

    		if (currentAttributeValues.contains(oldAttributeValue)) {
        		newAttributeValues.remove(oldAttributeValue);
        	}

        	if (!newAttributeValues.contains(newAttributeValue)) {
        		newAttributeValues.add(newAttributeValue);
        	}

        	customAttribute.setValues(newAttributeValues);
        }

		return updateUser(user);
    }

	public CustomAttribute getCustomAttribute(User user, String attributeName) {
		for (CustomAttribute customAttribute : user.getCustomAttributes()) {
			if (StringHelper.equalsIgnoreCase(attributeName, customAttribute.getName())) {
				return customAttribute;
			}
		}

		return null;
	}

	public void setCustomAttribute(User user, String attributeName, String attributeValue) {
		CustomAttribute customAttribute = getCustomAttribute(user, attributeName);
		
		if (customAttribute == null) {
			customAttribute = new CustomAttribute(attributeName);
			user.getCustomAttributes().add(customAttribute);
		}
		
		customAttribute.setValue(attributeValue);
	}
//
//    // this method must be called only if app mode = MEMORY, in ldap case it's anyway persisted in ldap.
//    public boolean saveLongLivedToken(String userId, PersistentJwt longLivedToken) {
//        log.debug("Saving long-lived access token: userId = {}", userId);
//        boolean succeed = false;
//
//        User user = getUser(userId);
//        if (user != null) {
//            int nTokens = 0;
//            if (user.getOxAuthPersistentJwt() != null) {
//                nTokens = user.getOxAuthPersistentJwt().length;
//            }
//            nTokens++;
//            String[] persistentJwts = new String[nTokens];
//            if (user.getOxAuthPersistentJwt() != null) {
//                for (int i = 0; i < user.getOxAuthPersistentJwt().length; i++) {
//                    persistentJwts[i] = user.getOxAuthPersistentJwt()[i];
//                }
//            }
//            persistentJwts[nTokens - 1] = longLivedToken.toString();
//
//            user.setOxAuthPersistentJwt(persistentJwts);
//            ldapEntryManager.merge(user);
//            succeed = true;
//        }
//
//        return succeed;
//    }

    public List<User> getUsersWithPersistentJwts() {
        String baseDN = getPeopleBaseDn();
        Filter filter = Filter.createPresenceFilter("oxAuthPersistentJWT");

        return persistenceEntryManager.findEntries(baseDN, User.class, filter);
    }

    public String getDnForUser(String inum) {
		String peopleDn = getPeopleBaseDn();
		if (StringHelper.isEmpty(inum)) {
			return peopleDn;
		}

		return String.format("inum=%s,%s", inum, peopleDn);
	}

	public String getUserInumByDn(String dn) {
		if (StringHelper.isEmpty(dn)) {
			return null;
		}

		String peopleDn = getPeopleBaseDn();
		if (!dn.toLowerCase().endsWith(peopleDn.toLowerCase())) {
			return null;
		}
		String firstDnPart = dn.substring(0, dn.length() - peopleDn.length());
		
		String[] dnParts = firstDnPart.split(",");
		if (dnParts.length == 0) {
			return null;
		}
		
		String userInumPart = dnParts[dnParts.length - 1];
		String[] userInumParts = userInumPart.split("=");
		if ((userInumParts.length == 2) && StringHelper.equalsIgnoreCase(userInumParts[0], "inum")) {
			return userInumParts[1];
		}

		return null;
	}

	public String encodeGeneralizedTime(Date date) {
		String baseDn = getDnForUser(null);
		return persistenceEntryManager.encodeTime(baseDn, date);
	}

	public Date decodeGeneralizedTime(String date) {
		String baseDn = getDnForUser(null);
		return persistenceEntryManager.decodeTime(baseDn, date);
	}

	protected abstract List<String> getPersonCustomObjectClassList();

	protected abstract String getPeopleBaseDn();
}
