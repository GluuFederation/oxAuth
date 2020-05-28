/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.ldap.ClientAuthorization;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.search.filter.Filter;
import org.gluu.service.CacheService;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.*;

/**
 * @author Javier Rojas Blum
 * @version March 4, 2020
 */
@Named
public class ClientAuthorizationsService {

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager ldapEntryManager;

    @Inject
    private CacheService cacheService;

    @Inject
    private ClientService clientService;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private AppConfiguration appConfiguration;

    public void addBranch() {
        SimpleBranch branch = new SimpleBranch();
        branch.setOrganizationalUnitName("authorizations");
        branch.setDn(createDn(null));

        ldapEntryManager.persist(branch);
    }

    public boolean containsBranch() {
        return ldapEntryManager.contains(createDn(null), SimpleBranch.class);
    }

    public void prepareBranch() {
        String baseDn = createDn(null);
        if (!ldapEntryManager.hasBranchesSupport(baseDn)) {
        	return;
        }

        // Create client authorizations branch if needed
        if (!containsBranch()) {
            addBranch();
        }
    }

    public ClientAuthorization find(String userInum, String clientId, boolean persistInLdap) {
        if (persistInLdap) {
            prepareBranch();

            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter("oxAuthClientId", clientId),
                    Filter.createEqualityFilter("oxAuthUserId", userInum)
            );

            List<ClientAuthorization> entries = ldapEntryManager.findEntries(staticConfiguration.getBaseDn().getAuthorizations(), ClientAuthorization.class, filter);
            if (entries != null && !entries.isEmpty()) {
                // if more then one entry then it's problem, non-deterministic behavior, id must be unique
                if (entries.size() > 1) {
                    log.error("Found more then one client authorization entry by client Id: {}" + clientId);
                    for (ClientAuthorization entry : entries) {
                        log.error(entry.toString());
                    }
                }
                return entries.get(0);
            }
        } else {
            String key = getCacheKey(userInum, clientId);
            Object cacheOjb = cacheService.get(key);
            if (cacheOjb instanceof ClientAuthorization) {
                return (ClientAuthorization) cacheOjb;
            }
        }

        return null;
    }

    public void clearAuthorizations(ClientAuthorization clientAuthorization, boolean persistInLdap) {
        if (clientAuthorization == null) {
            return;
        }

        if (persistInLdap) {
            ldapEntryManager.remove(clientAuthorization);
        } else {
            String key = getCacheKey(clientAuthorization.getUserId(), clientAuthorization.getClientId());
            cacheService.remove(key);
        }
    }

    public void add(String userInum, String clientId, Set<String> scopes, boolean persist) {
        log.trace("Attempting to add client authorization, scopes:" + scopes + ", clientId: " + clientId + ", userInum: " + userInum + ", persist: " + persist);
        Client client = clientService.getClient(clientId);

        if (persist) {
            // oxAuth #441 Pre-Authorization + Persist Authorizations... don't write anything
            // If a client has pre-authorization=true, there is no point to create the entry under
            // ou=clientAuthorizations it will negatively impact performance, grow the size of the
            // ldap database, and serve no purpose.
            prepareBranch();

            ClientAuthorization clientAuthorization = find(userInum, clientId, persist);

            if (clientAuthorization == null) {
                clientAuthorization = new ClientAuthorization();
                clientAuthorization.setId(UUID.randomUUID().toString());
                clientAuthorization.setClientId(clientId);
                clientAuthorization.setUserId(userInum);
                clientAuthorization.setScopes(scopes.toArray(new String[scopes.size()]));
                clientAuthorization.setDn(createDn(clientAuthorization.getId()));
                clientAuthorization.setDeletable(!client.getAttributes().getKeepClientAuthorizationAfterExpiration());
                clientAuthorization.setExpirationDate(client.getExpirationDate());
                clientAuthorization.setTtl(appConfiguration.getDynamicRegistrationExpirationTime());

                ldapEntryManager.persist(clientAuthorization);
            } else if (clientAuthorization.getScopes() != null) {
                Set<String> set = new HashSet<String>(scopes);
                set.addAll(Arrays.asList(clientAuthorization.getScopes()));
                clientAuthorization.setScopes(set.toArray(new String[set.size()]));

                ldapEntryManager.merge(clientAuthorization);
            }
        } else {
            // Put client authorization in cache. oxAuth #662.
            ClientAuthorization clientAuthorizations = find(userInum, clientId, persist);
            String key = getCacheKey(userInum, clientId);

            if (clientAuthorizations == null) {
                clientAuthorizations = new ClientAuthorization();
                clientAuthorizations.setId(UUID.randomUUID().toString());
                clientAuthorizations.setClientId(clientId);
                clientAuthorizations.setUserId(userInum);
                clientAuthorizations.setScopes(scopes.toArray(new String[scopes.size()]));
                clientAuthorizations.setDn(createDn(clientAuthorizations.getId()));
                clientAuthorizations.setDeletable(!client.getAttributes().getKeepClientAuthorizationAfterExpiration());
                clientAuthorizations.setExpirationDate(client.getExpirationDate());

                cacheService.put(key, clientAuthorizations);
            } else if (clientAuthorizations.getScopes() != null) {
                Set<String> set = new HashSet<String>(scopes);
                set.addAll(Arrays.asList(clientAuthorizations.getScopes()));
                clientAuthorizations.setScopes(set.toArray(new String[set.size()]));

                cacheService.put(key, clientAuthorizations);
            }
        }
    }

    public String createDn(String oxId) {
        String baseDn = staticConfiguration.getBaseDn().getAuthorizations();
        if (StringHelper.isEmpty(oxId)) {
            return baseDn;
        }
        return String.format("oxId=%s,%s", oxId, baseDn);
    }

    private String getCacheKey(String userInum, String clientId) {
        return userInum + "_" + clientId;
    }
}
