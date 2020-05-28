package org.gluu.oxauth.service;

import org.gluu.oxauth.model.common.PairwiseIdType;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.util.SubjectIdentifierGenerator;
import org.gluu.oxauth.service.common.UserService;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.search.filter.Filter;
import org.gluu.util.StringHelper;
import org.oxauth.persistence.model.PairwiseIdentifier;
import org.slf4j.Logger;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.inject.Named;
import java.net.URI;
import java.util.List;

/**
 * @author Javier Rojas Blum
 * @version May 7, 2019
 */
@Stateless
@Named
public class PairwiseIdentifierService {

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager ldapEntryManager;

    @Inject
    private UserService userService;

    @Inject
    private AppConfiguration appConfiguration;

    public void addBranch(final String userInum) {
        SimpleBranch branch = new SimpleBranch();
        branch.setOrganizationalUnitName("pairwiseIdentifiers");
        branch.setDn(getBaseDnForPairwiseIdentifiers(userInum));

        ldapEntryManager.persist(branch);
    }

    public boolean containsBranch(final String userInum) {
        return ldapEntryManager.contains(getBaseDnForPairwiseIdentifiers(userInum), SimpleBranch.class);
    }

    public void prepareBranch(final String userInum) {
        if (!ldapEntryManager.hasBranchesSupport(userService.getDnForUser(userInum))) {
            return;
        }

        // Create pairwise identifier branch if needed
        if (!containsBranch(userInum)) {
            addBranch(userInum);
        }
    }

    public PairwiseIdentifier findPairWiseIdentifier(String userInum, String sectorIdentifierUri, String clientId) throws Exception {
        PairwiseIdType pairwiseIdType = PairwiseIdType.fromString(appConfiguration.getPairwiseIdType());
        String sectorIdentifier = URI.create(sectorIdentifierUri).getHost();

        if (PairwiseIdType.PERSISTENT == pairwiseIdType) {
            prepareBranch(userInum);

            String baseDnForPairwiseIdentifiers = getBaseDnForPairwiseIdentifiers(userInum);

            Filter filter = null;
            if (appConfiguration.isShareSubjectIdBetweenClientsWithSameSectorId()) {
                filter = Filter.createEqualityFilter("oxSectorIdentifier", sectorIdentifier);
            } else {
                Filter sectorIdentifierFilter = Filter.createEqualityFilter("oxSectorIdentifier", sectorIdentifier);
                Filter clientIdFilter = Filter.createEqualityFilter("oxAuthClientId", clientId);
                Filter userInumFilter = Filter.createEqualityFilter("oxAuthUserId", userInum);

                filter = Filter.createANDFilter(sectorIdentifierFilter, clientIdFilter, userInumFilter);
            }

            List<PairwiseIdentifier> entries = ldapEntryManager.findEntries(baseDnForPairwiseIdentifiers, PairwiseIdentifier.class, filter);
            if (entries != null && !entries.isEmpty()) {
                // if more then one entry then it's problem, non-deterministic behavior, id must be unique
                if (entries.size() > 1) {
                    log.error("Found more then one pairwise identifier by sector identifier: {}" + sectorIdentifier);
                    for (PairwiseIdentifier pairwiseIdentifier : entries) {
                        log.error("PairwiseIdentifier: {}", pairwiseIdentifier);
                    }
                }
                return entries.get(0);
            }
        } else { // PairwiseIdType.ALGORITHMIC
            String key = appConfiguration.getPairwiseCalculationKey();
            String salt = appConfiguration.getPairwiseCalculationSalt();
            String localAccountId = appConfiguration.isShareSubjectIdBetweenClientsWithSameSectorId() ?
                    userInum : userInum + clientId;

            String calculatedSub = SubjectIdentifierGenerator.generatePairwiseSubjectIdentifier(
                    sectorIdentifierUri, localAccountId, key, salt, appConfiguration);

            PairwiseIdentifier pairwiseIdentifier = new PairwiseIdentifier(sectorIdentifierUri, clientId, userInum);
            pairwiseIdentifier.setId(calculatedSub);

            return pairwiseIdentifier;
        }

        return null;
    }

    public void addPairwiseIdentifier(String userInum, PairwiseIdentifier pairwiseIdentifier) {
        prepareBranch(userInum);
        userService.addUserAttributeByUserInum(userInum, "oxPPID", pairwiseIdentifier.getId());

        ldapEntryManager.persist(pairwiseIdentifier);
    }

    public String getDnForPairwiseIdentifier(String oxId, String userInum) {
        String baseDn = getBaseDnForPairwiseIdentifiers(userInum);
        if (StringHelper.isEmpty(oxId)) {
            return baseDn;
        }
        return String.format("oxId=%s,%s", oxId, baseDn);
    }

    public String getBaseDnForPairwiseIdentifiers(String userInum) {
        final String userBaseDn = userService.getDnForUser(userInum); // "ou=pairwiseIdentifiers,inum=1234,ou=people,o=gluu"
        return String.format("ou=pairwiseIdentifiers,%s", userBaseDn);
    }

}
