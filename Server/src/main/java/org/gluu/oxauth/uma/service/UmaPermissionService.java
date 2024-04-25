/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.uma.service;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.uma.UmaPermissionList;
import org.gluu.oxauth.model.uma.persistence.UmaPermission;
import org.gluu.oxauth.model.util.Pair;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.search.filter.Filter;
import org.gluu.util.INumGenerator;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.*;

/**
 * Holds permission tokens and permissions
 *
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class UmaPermissionService {

    private static final String ORGUNIT_OF_RESOURCE_PERMISSION = "uma_permission";
    private static final int DEFAULT_TICKET_LIFETIME = 3600;

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager ldapEntryManager;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private UmaScopeService scopeService;

    @Inject
    private AppConfiguration appConfiguration;

    public static String getDn(String clientDn, String ticket) {
        return String.format("oxTicket=%s,%s", ticket, getBranchDn(clientDn));
    }

    public static String getBranchDn(String clientDn) {
        return String.format("ou=%s,%s", ORGUNIT_OF_RESOURCE_PERMISSION, clientDn);
    }

    private List<UmaPermission> createPermissions(UmaPermissionList permissions, Pair<Date, Integer> expirationDate) {
        final String configurationCode = INumGenerator.generate(8) + "." + System.currentTimeMillis();

        final String ticket = generateNewTicket();
        List<UmaPermission> result = new ArrayList<UmaPermission>();
        for (org.gluu.oxauth.model.uma.UmaPermission permission : permissions) {
            UmaPermission p = new UmaPermission(permission.getResourceId(), scopeService.getScopeDNsByIdsAndAddToLdapIfNeeded(permission.getScopes()), ticket, configurationCode, expirationDate);
            if (permission.getParams() != null && !permission.getParams().isEmpty()) {
                p.getAttributes().putAll(permission.getParams());
            }
            result.add(p);
        }

        return result;
    }

    public String generateNewTicket() {
       return UUID.randomUUID().toString();
    }

    public String addPermission(UmaPermissionList permissionList, String clientDn) {
        try {
            List<UmaPermission> created = createPermissions(permissionList, ticketExpirationDate());
            for (UmaPermission permission : created) {
                addPermission(permission, clientDn);
            }
            return created.get(0).getTicket();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;
        }
    }

    public Pair<Date, Integer> ticketExpirationDate() {
        int lifeTime = appConfiguration.getUmaTicketLifetime();
        if (lifeTime <= 0) {
            lifeTime = DEFAULT_TICKET_LIFETIME;
        }

        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, lifeTime);
        return new Pair<>(calendar.getTime(), lifeTime);
    }

    public void addPermission(UmaPermission permission, String clientDn) {
        try {
            addBranchIfNeeded(clientDn);
            permission.setDn(getDn(clientDn, permission.getTicket()));
            ldapEntryManager.persist(permission);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void merge(UmaPermission permission) {
        permission.resetTtlFromExpirationDate();
        ldapEntryManager.merge(permission);
    }

    public void mergeSilently(UmaPermission permission) {
        try {
            permission.resetTtlFromExpirationDate();
            ldapEntryManager.merge(permission);
        } catch (Exception e) {
            log.error("Failed to persist permission: " + permission, e);
        }
    }

    public List<UmaPermission> getPermissionsByTicket(String ticket) {
        try {
            final String baseDn = staticConfiguration.getBaseDn().getClients();
            final Filter filter = Filter.createEqualityFilter("oxTicket", ticket);
            return ldapEntryManager.findEntries(baseDn, UmaPermission.class, filter);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public void deletePermission(String ticket) {
        try {
            final List<UmaPermission> permissions = getPermissionsByTicket(ticket);
            for (UmaPermission p : permissions) {
                ldapEntryManager.remove(p);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void addBranch(String clientDn) {
    	String branchDn = getBranchDn(clientDn);
        if (!containsBranch(branchDn)) {
        	final SimpleBranch branch = new SimpleBranch();
	        branch.setOrganizationalUnitName(ORGUNIT_OF_RESOURCE_PERMISSION);
	        branch.setDn(branchDn);
	        ldapEntryManager.persist(branch);
        }
    }

    public void addBranchIfNeeded(String clientDn) {
        if (!ldapEntryManager.hasBranchesSupport(clientDn)) {
            return;
        }
        if (!containsBranch(clientDn)) {
            addBranch(clientDn);
        }
    }

    public boolean containsBranch(String clientDn) {
        return ldapEntryManager.contains(getBranchDn(clientDn), SimpleBranch.class);
    }

    public String changeTicket(List<UmaPermission> permissions, Map<String, String> attributes) {
        String newTicket = generateNewTicket();

        for (UmaPermission permission : permissions) {
            ldapEntryManager.remove(permission);

            String dn = String.format("oxTicket=%s,%s", newTicket, StringUtils.substringAfter(permission.getDn(), ","));
            permission.setTicket(newTicket);
            permission.setDn(dn);
            permission.setAttributes(attributes);
            ldapEntryManager.persist(permission);
            log.trace("New ticket: " + newTicket + ", old permission: " + dn);
        }

        return newTicket;
    }
}
