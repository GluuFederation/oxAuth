/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.inject.Named;

import org.gluu.model.ApplicationType;
import org.gluu.model.metric.ldap.MetricEntry;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.fido.u2f.DeviceRegistration;
import org.gluu.oxauth.model.fido.u2f.RegisterRequestMessageLdap;
import org.gluu.oxauth.model.ldap.ClientAuthorization;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.model.uma.persistence.UmaResource;
import org.gluu.oxauth.service.fido.u2f.RequestService;
import org.gluu.oxauth.uma.authorization.UmaPCT;
import org.gluu.oxauth.uma.service.UmaPctService;
import org.gluu.oxauth.uma.service.UmaResourceService;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.search.filter.Filter;
import org.gluu.service.cache.CacheProvider;
import org.gluu.service.cdi.async.Asynchronous;
import org.gluu.service.cdi.event.CleanerEvent;
import org.gluu.service.cdi.event.Scheduled;
import org.gluu.service.timer.event.TimerEvent;
import org.gluu.service.timer.schedule.TimerSchedule;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Maps;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version August 9, 2017
 */
@ApplicationScoped
public class CleanerTimer {

    public final static int BATCH_SIZE = 1000;
    private final static int DEFAULT_INTERVAL = 30; // 30 seconds

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager entryManager;

    @Inject
    private UmaPctService umaPctService;

    @Inject
    private UmaResourceService umaResourceService;

    @Inject
    private CacheProvider cacheProvider;

    @Inject
    @Named("u2fRequestService")
    private RequestService u2fRequestService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private Event<TimerEvent> cleanerEvent;

	@Inject
	private MetricService metricService;

    private long lastFinishedTime;

    private AtomicBoolean isActive;

    public void initTimer() {
        log.debug("Initializing Cleaner Timer");
        this.isActive = new AtomicBoolean(false);

        // Schedule to start cleaner every 30 seconds
        cleanerEvent.fire(
                new TimerEvent(new TimerSchedule(DEFAULT_INTERVAL, DEFAULT_INTERVAL), new CleanerEvent(), Scheduled.Literal.INSTANCE));

        this.lastFinishedTime = System.currentTimeMillis();
    }

    @Asynchronous
    public void process(@Observes @Scheduled CleanerEvent cleanerEvent) {
        if (this.isActive.get()) {
            return;
        }

        if (!this.isActive.compareAndSet(false, true)) {
            return;
        }

        try {
            processImpl();
        } finally {
            this.isActive.set(false);
        }
    }

    private boolean isStartProcess() {
        int interval = appConfiguration.getCleanServiceInterval();
        if (interval < 0) {
            log.info("Cleaner Timer is disabled.");
            log.warn("Cleaner Timer Interval (cleanServiceInterval in oxauth configuration) is negative which turns OFF internal clean up by the server. Please set it to positive value if you wish internal clean up timer run.");
            return false;
        }

        long cleaningInterval = interval * 1000;

        long timeDiffrence = System.currentTimeMillis() - this.lastFinishedTime;

        return timeDiffrence >= cleaningInterval;
    }

    public void processImpl() {
        try {
            if (!isStartProcess()) {
                log.trace("Starting conditions aren't reached");
                return;
            }

            int chunkSize = appConfiguration.getCleanServiceBatchChunkSize();
            if (chunkSize <= 0)
                chunkSize = BATCH_SIZE;

            Date now = new Date();

            final Set<String> processedBaseDns = new HashSet<>();
            for (Map.Entry<String, Class<?>> baseDn : createCleanServiceBaseDns().entrySet()) {
                try {
                    if (entryManager.hasExpirationSupport(baseDn.getKey())) {
                        continue;
                    }

                    String processedBaseDn = baseDn.getKey() + "_" + (baseDn.getValue() == null ? "" : baseDn.getValue().getSimpleName());
                    if (processedBaseDns.contains(processedBaseDn)) {
                        log.warn("baseDn: {}, already processed. Please fix cleaner configuration! Skipping second run...", baseDn);
                        continue;
                    }

                    processedBaseDns.add(processedBaseDn);

                    log.debug("Start clean up for baseDn: " + baseDn.getValue() + ", class: " + baseDn.getValue());
                    final Stopwatch started = Stopwatch.createStarted();

                    int removed = cleanup(baseDn, now, chunkSize);

                    log.debug("Finished clean up for baseDn: {}, takes: {}ms, removed items: {}", baseDn, started.elapsed(TimeUnit.MILLISECONDS), removed);
                } catch (Exception e) {
                    log.error("Failed to process clean up for baseDn: " + baseDn + ", class: " + baseDn.getValue(), e);
                }
            }

            processCache(now);

            this.lastFinishedTime = System.currentTimeMillis();
        } catch (Exception e) {
            log.error("Failed to process clean up.", e);
        }
    }

    private Map<String, Class<?>> createCleanServiceBaseDns() {
        final String u2fBase = staticConfiguration.getBaseDn().getU2fBase();

        final Map<String, Class<?>> cleanServiceBaseDns = Maps.newHashMap();

        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getClients(), Client.class);
        cleanServiceBaseDns.put(umaPctService.branchBaseDn(), UmaPCT.class);
        cleanServiceBaseDns.put(umaResourceService.getBaseDnForResource(), UmaResource.class);
        cleanServiceBaseDns.put(String.format("ou=registration_requests,%s", u2fBase), RegisterRequestMessageLdap.class);
        cleanServiceBaseDns.put(String.format("ou=registered_devices,%s", u2fBase), DeviceRegistration.class);
        // cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getPeople(), User.class);
        cleanServiceBaseDns.put(metricService.buildDn(null, null, ApplicationType.OX_AUTH), MetricEntry.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getTokens(), TokenLdap.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getAuthorizations(), ClientAuthorization.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getScopes(), Scope.class);
        cleanServiceBaseDns.put(staticConfiguration.getBaseDn().getSessions(), SessionId.class);

        return cleanServiceBaseDns;
    }

    public int cleanup(final Map.Entry<String, Class<?>> baseDn, final Date now, final int batchSize) {
        try {
            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter("del", true),
                    Filter.createLessOrEqualFilter("exp", entryManager.encodeTime(baseDn.getKey(), now)));

            int removedCount = entryManager.remove(baseDn.getKey(), baseDn.getValue(), filter, batchSize);
            log.trace("Removed " + removedCount + " entries from " + baseDn.getKey());
            return removedCount;
        } catch (Exception e) {
            log.error("Failed to perform clean up.", e);
        }

        return 0;
    }

    private void processCache(Date now) {
        try {
            cacheProvider.cleanup(now);
        } catch (Exception e) {
            log.error("Failed to clean up cache.", e);
        }
    }
}
