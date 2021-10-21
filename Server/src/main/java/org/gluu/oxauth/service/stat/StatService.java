package org.gluu.oxauth.service.stat;

import net.agkn.hll.HLL;
import org.apache.commons.lang.StringUtils;
import org.gluu.net.InetAddressUtility;
import org.gluu.oxauth.model.common.GrantType;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.stat.Stat;
import org.gluu.oxauth.model.stat.StatEntry;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.exception.EntryPersistenceException;
import org.gluu.persist.model.base.SimpleBranch;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class StatService {

    // January - 202001, December - 202012
    private static final SimpleDateFormat PERIOD_DATE_FORMAT = new SimpleDateFormat("yyyyMM");
    private static final int regwidth = 5;
    private static final int log2m = 15;

    public static final String ACCESS_TOKEN_KEY = "access_token";
    public static final String ID_TOKEN_KEY = "id_token";
    public static final String REFRESH_TOKEN_KEY = "refresh_token";
    public static final String UMA_TOKEN_KEY = "uma_token";

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager entryManager;

    @Inject
    private StaticConfiguration staticConfiguration;

    private String nodeId;
    private String monthlyDn;
    private StatEntry currentEntry;
    private HLL hll;
    private ConcurrentMap<String, Map<String, Long>> tokenCounters;

    private boolean initialized = false;

    @PostConstruct
    public void create() {
        initialized = false;
    }

    public boolean init() {
        try {
            log.info("Initializing Stat Service");
            initNodeId();
            if (StringUtils.isBlank(nodeId)) {
                log.error("Failed to initialize stat service. statNodeId is not set in configuration.");
                return false;
            }
            if (StringUtils.isBlank(getBaseDn())) {
                log.error("Failed to initialize stat service. 'stat' base dn is not set in configuration.");
                return false;
            }

            final Date now = new Date();
            prepareMonthlyBranch(now);
            log.trace("Monthly branch created: " + monthlyDn);

            setupCurrentEntry(now);
            log.info("Initialized Stat Service");
            initialized = true;
            return true;
        } catch (Exception e) {
            log.error("Failed to initialize Stat Service.", e);
            return false;
        }
    }

    public void updateStat() {
        if (!initialized) {
            return;
        }

        log.trace("Started updateStat ...");

        Date now = new Date();
        prepareMonthlyBranch(now);

        setupCurrentEntry(now);

        final Stat stat = currentEntry.getStat();
        stat.setTokenCountPerGrantType(tokenCounters);
        stat.setLastUpdatedAt(now.getTime());

        synchronized (hll) {
            currentEntry.setUserHllData(Base64.getEncoder().encodeToString(hll.toBytes()));
        }
        entryManager.merge(currentEntry);

        log.trace("Finished updateStat.");
    }

    private void setupCurrentEntry() {
        setupCurrentEntry(new Date());
    }

    private void setupCurrentEntry(Date now) {
        final String month = PERIOD_DATE_FORMAT.format(now);
        String dn = String.format("jansId=%s,%s", nodeId, monthlyDn); // jansId=<id>,ou=yyyyMM,ou=stat,o=gluu

        if (currentEntry != null && month.equals(currentEntry.getStat().getMonth())) {
            return;
        }

        try {
            StatEntry entryFromPersistence = entryManager.find(StatEntry.class, dn);
            if (entryFromPersistence != null && month.equals(entryFromPersistence.getStat().getMonth())) {
                hll = HLL.fromBytes(Base64.getDecoder().decode(entryFromPersistence.getUserHllData()));
                tokenCounters = new ConcurrentHashMap<>(entryFromPersistence.getStat().getTokenCountPerGrantType());
                currentEntry = entryFromPersistence;
                log.trace("Stat entry loaded.");
                return;
            }
        } catch (EntryPersistenceException e) {
            log.trace("Stat entry is not found in persistence.");
        }

        if (currentEntry == null) {
            log.trace("Creating stat entry ...");
            hll = newHll();
            tokenCounters = new ConcurrentHashMap<>();

            currentEntry = new StatEntry();
            currentEntry.setId(nodeId);
            currentEntry.setDn(dn);
            currentEntry.setUserHllData(Base64.getEncoder().encodeToString(hll.toBytes()));
            currentEntry.getStat().setMonth(PERIOD_DATE_FORMAT.format(new Date()));
            entryManager.persist(currentEntry);
            log.trace("Created stat entry. nodeId:" + nodeId);
        }
    }

    public HLL newHll() {
        return new HLL(log2m, regwidth);
    }

    private void initNodeId() {
        if (StringUtils.isNotBlank(nodeId)) {
            return;
        }

        try {
            nodeId = InetAddressUtility.getMACAddressOrNull();
            if (StringUtils.isNotBlank(nodeId)) {
                log.trace("NodeId created: " + nodeId);
                return;
            }

            nodeId = UUID.randomUUID().toString();
            log.trace("NodeId created: " + nodeId);
        } catch (Exception e) {
            log.error("Failed to identify nodeId.", e);
            nodeId = UUID.randomUUID().toString();
        }
    }

    public String getNodeId() {
        return nodeId;
    }

    public String getBaseDn() {
        return staticConfiguration.getBaseDn().getStat();
    }

    private void prepareMonthlyBranch(Date now) {
        final String baseDn = getBaseDn();
        final String month = PERIOD_DATE_FORMAT.format(now); // yyyyMM
        monthlyDn = String.format("ou=%s,%s", month, baseDn); // ou=yyyyMM,ou=stat,o=gluu

        if (!entryManager.hasBranchesSupport(baseDn)) {
            return;
        }

        try {
            if (!entryManager.contains(monthlyDn, SimpleBranch.class)) { // Create ou=yyyyMM branch if needed
                createBranch(monthlyDn, month);
            }
        } catch (Exception e) {
            log.error("Failed to prepare monthly branch: " + monthlyDn, e);
            throw e;
        }
    }

    public void createBranch(String branchDn, String ou) {
        try {
            SimpleBranch branch = new SimpleBranch();
            branch.setOrganizationalUnitName(ou);
            branch.setDn(branchDn);

            entryManager.persist(branch);
        } catch (EntryPersistenceException ex) {
            // Check if another process added this branch already
            if (!entryManager.contains(branchDn, SimpleBranch.class)) {
                throw ex;
            }
        }
    }

    public void reportActiveUser(String id) {
        if (!initialized) {
            return;
        }

        if (StringUtils.isBlank(id)) {
            return;
        }

        final int hash = id.hashCode();
        try {
            setupCurrentEntry();
            synchronized (hll) {
                hll.addRaw(hash);
            }
        } catch (Exception e) {
            log.error("Failed to report active user, id: " + id + ", hash: " + hash, e);
        }
    }

    public void reportAccessToken(GrantType grantType) {
        reportToken(grantType, ACCESS_TOKEN_KEY);
    }

    public void reportIdToken(GrantType grantType) {
        reportToken(grantType, ID_TOKEN_KEY);
    }

    public void reportRefreshToken(GrantType grantType) {
        reportToken(grantType, REFRESH_TOKEN_KEY);
    }

    public void reportUmaToken(GrantType grantType) {
        reportToken(grantType, UMA_TOKEN_KEY);
    }


    private void reportToken(GrantType grantType, String tokenKey) {
        if (!initialized) {
            return;
        }

        if (grantType == null || tokenKey == null) {
            return;
        }
        if (tokenCounters == null) {
            log.error("Stat service is not initialized.");
            return;
        }

        Map<String, Long> tokenMap = tokenCounters.computeIfAbsent(grantType.getValue(), k -> new ConcurrentHashMap<>());

        Long counter = tokenMap.get(tokenKey);

        if (counter == null) {
            counter = 1L;
        } else {
            counter++;
        }

        tokenMap.put(tokenKey, counter);
    }
}