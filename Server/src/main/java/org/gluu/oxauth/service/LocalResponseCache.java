package org.gluu.oxauth.service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.service.cdi.event.AuthConfigurationEvent;
import org.gluu.service.cdi.async.Asynchronous;
import org.gluu.service.cdi.event.Scheduled;
import org.json.JSONObject;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
@Named
public class LocalResponseCache {

    public static final int DEFAULT_DISCOVERY_LIFETIME = 60;
    public static final int DEFAULT_SECTOR_IDENTIFIER_LIFETIME = 1440; // 1 day

    private static final String DISCOVERY_CACHE_KEY = "DISCOVERY_CACHE_KEY";

    @Inject
    private AppConfiguration appConfiguration;
    @Inject
    private Logger log;

    private final AtomicBoolean rebuilding = new AtomicBoolean(false);

    private Cache<String, JSONObject> discoveryCache = CacheBuilder.newBuilder()
            .expireAfterWrite(DEFAULT_DISCOVERY_LIFETIME, TimeUnit.MINUTES).build();
    private Cache<String, List<String>> sectorIdentifierCache = CacheBuilder.newBuilder()
            .expireAfterWrite(DEFAULT_SECTOR_IDENTIFIER_LIFETIME, TimeUnit.MINUTES).build();


    private int currentDiscoveryLifetime = DEFAULT_DISCOVERY_LIFETIME;
    private int currentSectorIdentifierLifetime = DEFAULT_SECTOR_IDENTIFIER_LIFETIME;

    @Asynchronous
    public void reloadConfigurationTimerEvent(@Observes @Scheduled AuthConfigurationEvent authConfigurationEvent) {
        try {
            if (rebuilding.get())
                return;

            rebuilding.set(true);

            if (currentDiscoveryLifetime != appConfiguration.getDiscoveryCacheLifetimeInMinutes()) {
                currentDiscoveryLifetime = appConfiguration.getDiscoveryCacheLifetimeInMinutes();
                discoveryCache = CacheBuilder.newBuilder()
                        .expireAfterWrite(appConfiguration.getDiscoveryCacheLifetimeInMinutes(), TimeUnit.MINUTES).build();
                log.trace("Re-created discovery cache with lifetime: " + appConfiguration.getDiscoveryCacheLifetimeInMinutes());
            }
            if (currentSectorIdentifierLifetime != appConfiguration.getSectorIdentifierCacheLifetimeInMinutes()) {
                currentSectorIdentifierLifetime = appConfiguration.getSectorIdentifierCacheLifetimeInMinutes();
                sectorIdentifierCache = CacheBuilder.newBuilder()
                        .expireAfterWrite(appConfiguration.getSectorIdentifierCacheLifetimeInMinutes(), TimeUnit.MINUTES).build();
                log.trace("Re-created sector identifier cache with lifetime: " + appConfiguration.getSectorIdentifierCacheLifetimeInMinutes());
            }
        } finally {
            rebuilding.set(false);
        }

    }

    public List<String> getSectorRedirectUris(String sectorIdentifierUri) {
        if (sectorIdentifierCache == null || rebuilding.get())
            return null;
        return sectorIdentifierCache.getIfPresent(sectorIdentifierUri);
    }

    public void putSectorRedirectUris(String sectorIdentifierUri, List<String> redirectUris) {
        if (sectorIdentifierCache == null || rebuilding.get())
            return;

        sectorIdentifierCache.put(sectorIdentifierUri, redirectUris);
    }

    public JSONObject getDiscoveryResponse() {
        if (discoveryCache == null || rebuilding.get())
            return null;
        return discoveryCache.getIfPresent(DISCOVERY_CACHE_KEY);
    }

    public void putDiscoveryResponse(JSONObject response) {
        if (discoveryCache == null || rebuilding.get())
            return;

        discoveryCache.put(DISCOVERY_CACHE_KEY, response);
    }
}
