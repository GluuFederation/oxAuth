/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.common;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.gluu.model.SmtpConfiguration;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.persist.PersistenceEntryManagerFactory;
import org.gluu.persist.model.PersistenceConfiguration;
import org.gluu.persist.service.PersistanceFactoryService;
import org.gluu.service.cache.CacheConfiguration;
import org.gluu.service.cache.InMemoryConfiguration;
import org.gluu.service.document.store.conf.DocumentStoreConfiguration;
import org.gluu.service.document.store.conf.LocalDocumentStoreConfiguration;
import org.oxauth.persistence.model.configuration.GluuConfiguration;
import org.slf4j.Logger;

/**
 * Holds factory methods to create services
 *
 * @author Yuriy Movchan Date: 05/22/2015
 */
@ApplicationScoped
public class ApplicationFactory {

    @Inject
    private Logger log;

    @Inject
    private ConfigurationService configurationService;

	@Inject
	private PersistanceFactoryService persistanceFactoryService;

	@Inject
	private PersistenceConfiguration persistenceConfiguration;

    @Inject
    private StaticConfiguration staticConfiguration;

    public static final String PERSISTENCE_AUTH_CONFIG_NAME = "persistenceAuthConfig";

    public static final String PERSISTENCE_ENTRY_MANAGER_NAME = "persistenceEntryManager";
    public static final String PERSISTENCE_METRIC_ENTRY_MANAGER_NAME = "persistenceMetricEntryManager";

    public static final String PERSISTENCE_AUTH_ENTRY_MANAGER_NAME = "persistenceAuthEntryManager";

    public static final String PERSISTENCE_METRIC_CONFIG_GROUP_NAME = "metric";

	@Produces @ApplicationScoped
	public CacheConfiguration getCacheConfiguration() {
		CacheConfiguration cacheConfiguration = configurationService.getConfiguration().getCacheConfiguration();
		if (cacheConfiguration == null || cacheConfiguration.getCacheProviderType() == null) {
			log.error("Failed to read cache configuration from DB. Please check configuration oxCacheConfiguration attribute " +
					"that must contain cache configuration JSON represented by CacheConfiguration.class. Appliance DN: " + configurationService.getConfiguration().getDn());
			log.info("Creating fallback IN-MEMORY cache configuration ... ");

			cacheConfiguration = new CacheConfiguration();
			cacheConfiguration.setInMemoryConfiguration(new InMemoryConfiguration());

			log.info("IN-MEMORY cache configuration is created.");
		}
		if (cacheConfiguration.getNativePersistenceConfiguration() != null) {
			if (!StringUtils.isEmpty(staticConfiguration.getBaseDn().getSessions())) {
				cacheConfiguration.getNativePersistenceConfiguration().setBaseDn(StringUtils.remove(staticConfiguration.getBaseDn().getSessions(), "ou=sessions,").trim());
			}
		}
		log.info("Cache configuration: " + cacheConfiguration);
		return cacheConfiguration;
	}

    @Produces @ApplicationScoped
   	public DocumentStoreConfiguration getDocumentStoreConfiguration() {
    	DocumentStoreConfiguration documentStoreConfiguration = configurationService.getConfiguration().getDocumentStoreConfiguration();
   		if ((documentStoreConfiguration == null) || (documentStoreConfiguration.getDocumentStoreType() == null)) {
   			log.error("Failed to read document store configuration from DB. Please check configuration oxDocumentStoreConfiguration attribute " +
   					"that must contain document store configuration JSON represented by DocumentStoreConfiguration.class. Appliance DN: " + configurationService.getConfiguration().getDn());
   			log.info("Creating fallback LOCAL document store configuration ... ");

   			documentStoreConfiguration = new DocumentStoreConfiguration();
   			documentStoreConfiguration.setLocalConfiguration(new LocalDocumentStoreConfiguration());

   			log.info("LOCAL document store configuration is created.");
		}

   		log.info("Document store configuration: " + documentStoreConfiguration);
   		return documentStoreConfiguration;
   	}

	@Produces @RequestScoped
	public SmtpConfiguration getSmtpConfiguration() {
		GluuConfiguration configuration = configurationService.getConfiguration();
		SmtpConfiguration smtpConfiguration = configuration.getSmtpConfiguration();
		
		if (smtpConfiguration == null) {
			return new SmtpConfiguration();
		}

		configurationService.decryptSmtpPassword(smtpConfiguration);
		configurationService.decryptKeyStorePassword(smtpConfiguration);

		return smtpConfiguration;
	}

    public PersistenceEntryManagerFactory getPersistenceEntryManagerFactory() {
        return persistanceFactoryService.getPersistenceEntryManagerFactory(persistenceConfiguration);
    }

    public PersistenceEntryManagerFactory getPersistenceEntryManagerFactory(Class<? extends PersistenceEntryManagerFactory> persistenceEntryManagerFactoryClass) {
        return persistanceFactoryService.getPersistenceEntryManagerFactory(persistenceEntryManagerFactoryClass);
    }

}