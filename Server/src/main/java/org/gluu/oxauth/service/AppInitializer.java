/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import com.google.common.collect.Lists;
import org.gluu.exception.ConfigurationException;
import org.gluu.model.AuthenticationScriptUsageType;
import org.gluu.model.SimpleProperty;
import org.gluu.model.custom.script.CustomScriptType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.ldap.GluuLdapConfiguration;
import org.gluu.oxauth.model.auth.AuthenticationMode;
import org.gluu.oxauth.model.config.ConfigurationFactory;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.service.cdi.event.AuthConfigurationEvent;
import org.gluu.oxauth.service.cdi.event.ReloadAuthScript;
import org.gluu.oxauth.service.ciba.CibaRequestsProcessorJob;
import org.gluu.oxauth.service.common.ApplicationFactory;
import org.gluu.oxauth.service.common.EncryptionService;
import org.gluu.oxauth.service.expiration.ExpirationNotificatorTimer;
import org.gluu.oxauth.service.external.ExternalAuthenticationService;
import org.gluu.oxauth.service.logger.LoggerService;
import org.gluu.oxauth.service.stat.StatService;
import org.gluu.oxauth.service.stat.StatTimer;
import org.gluu.oxauth.service.status.ldap.LdapStatusTimer;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.PersistenceEntryManagerFactory;
import org.gluu.persist.exception.BasePersistenceException;
import org.gluu.persist.ldap.impl.LdapEntryManagerFactory;
import org.gluu.persist.model.PersistenceConfiguration;
import org.gluu.service.PythonService;
import org.gluu.service.cdi.async.Asynchronous;
import org.gluu.service.cdi.event.ApplicationInitialized;
import org.gluu.service.cdi.event.ApplicationInitializedEvent;
import org.gluu.service.cdi.event.LdapConfigurationReload;
import org.gluu.service.cdi.event.Scheduled;
import org.gluu.service.cdi.util.CdiUtil;
import org.gluu.service.custom.lib.CustomLibrariesLoader;
import org.gluu.service.custom.script.CustomScriptManager;
import org.gluu.service.external.ExternalPersistenceExtensionService;
import org.gluu.service.metric.inject.ReportMetric;
import org.gluu.service.timer.QuartzSchedulerManager;
import org.gluu.service.timer.event.TimerEvent;
import org.gluu.service.timer.schedule.TimerSchedule;
import org.gluu.util.OxConstants;
import org.gluu.util.StringHelper;
import org.gluu.orm.util.properties.FileConfiguration;
import org.gluu.util.security.SecurityProviderUtility;
import org.gluu.util.security.StringEncrypter;
import org.gluu.util.security.StringEncrypter.EncryptionException;
import org.jboss.weld.util.reflection.ParameterizedTypeImpl;
import org.oxauth.persistence.model.configuration.GluuConfiguration;
import org.oxauth.persistence.model.configuration.oxIDPAuthConf;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.BeforeDestroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.ServletContext;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @author Yuriy Zabrovarnyy
 * @version 0.1, 24/10/2011
 */
@ApplicationScoped
@Named
public class AppInitializer {

	private final static int DEFAULT_INTERVAL = 30; // 30 seconds

	@Inject
	private Logger log;

	@Inject
	private BeanManager beanManager;

	@Inject
	private Event<String> event;

	@Inject
	private Event<ApplicationInitializedEvent> eventApplicationInitialized;

	@Inject
	private Event<TimerEvent> timerEvent;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME)
	private Instance<PersistenceEntryManager> persistenceEntryManagerInstance;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME)
	@ReportMetric
	private Instance<PersistenceEntryManager> persistenceMetricEntryManagerInstance;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME)
	private Instance<List<PersistenceEntryManager>> persistenceAuthEntryManagerInstance;

	@Inject
	@Named(ApplicationFactory.PERSISTENCE_AUTH_CONFIG_NAME)
	private Instance<List<GluuLdapConfiguration>> persistenceAuthConfigInstance;

	@Inject
	private ApplicationFactory applicationFactory;

	@Inject
	private Instance<AuthenticationMode> authenticationModeInstance;

	@Inject
	private Instance<EncryptionService> encryptionServiceInstance;

	@Inject
	private PythonService pythonService;

	@Inject
	private MetricService metricService;

	@Inject
	private CustomScriptManager customScriptManager;
	
	@Inject
	private ExternalPersistenceExtensionService externalPersistenceExtensionService;

	@Inject
	private ConfigurationFactory configurationFactory;

	@Inject
	private CleanerTimer cleanerTimer;

	@Inject
	private KeyGeneratorTimer keyGeneratorTimer;

    @Inject
    private StatService statService;

    @Inject
    private StatTimer statTimer;

	@Inject
    private ExpirationNotificatorTimer expirationNotificatorTimer;

	@Inject
	private CustomLibrariesLoader customLibrariesLoader;

	@Inject
	private LdapStatusTimer ldapStatusTimer;

	@Inject
	private QuartzSchedulerManager quartzSchedulerManager;

	@Inject
	private LoggerService loggerService;
	
	@Inject
	private ExternalAuthenticationService externalAuthenticationService;

	@Inject
	private AppConfiguration appConfiguration;

	@Inject
	private CibaRequestsProcessorJob cibaRequestsProcessorJob;

	private AtomicBoolean isActive;
	private long lastFinishedTime;
	private AuthenticationMode authenticationMode;

	private List<GluuLdapConfiguration> persistenceAuthConfigs;

	@PostConstruct
	public void createApplicationComponents() {
		SecurityProviderUtility.installBCProvider();
	}

	public void applicationInitialized(@Observes @Initialized(ApplicationScoped.class) Object init) {
		log.debug("Initializing application services");

		configurationFactory.create();

		PersistenceEntryManager localPersistenceEntryManager = persistenceEntryManagerInstance.get();
		log.trace("Attempting to use {}: {}", ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME, localPersistenceEntryManager.getOperationService());

		GluuConfiguration newConfiguration = loadConfiguration(localPersistenceEntryManager, "oxIDPAuthentication", "oxAuthenticationMode");

		this.persistenceAuthConfigs = loadPersistenceAuthConfigs(newConfiguration);

		// Initialize python interpreter
		pythonService.initPythonInterpreter(configurationFactory.getBaseConfiguration()
				.getString("pythonModulesDir", null));

		// Initialize script manager
		List<CustomScriptType> supportedCustomScriptTypes = Lists.newArrayList(CustomScriptType.values());

		supportedCustomScriptTypes.remove(CustomScriptType.CACHE_REFRESH);
		supportedCustomScriptTypes.remove(CustomScriptType.UPDATE_USER);
		supportedCustomScriptTypes.remove(CustomScriptType.USER_REGISTRATION);
		supportedCustomScriptTypes.remove(CustomScriptType.SCIM);
		supportedCustomScriptTypes.remove(CustomScriptType.IDP);

        statService.init();

		// Start timer
		initSchedulerService();

		// Schedule timer tasks
		metricService.initTimer();
		configurationFactory.initTimer();
		loggerService.initTimer();
		ldapStatusTimer.initTimer();
		cleanerTimer.initTimer();
		customScriptManager.initTimer(supportedCustomScriptTypes);
		keyGeneratorTimer.initTimer();
        statTimer.initTimer();
		expirationNotificatorTimer.initTimer();
		initTimer();
		initCibaRequestsProcessor();

		// Set default authentication method after
		setDefaultAuthenticationMethod(newConfiguration);

		// Notify plugins about finish application initialization
		eventApplicationInitialized.select(ApplicationInitialized.Literal.APPLICATION)
				.fire(new ApplicationInitializedEvent());
	}

	protected void initSchedulerService() {
		quartzSchedulerManager.start();

		String disableScheduler = System.getProperties().getProperty("gluu.disable.scheduler");
		if ((disableScheduler != null) && Boolean.valueOf(disableScheduler)) {
			this.log.warn("Suspending Quartz Scheduler Service...");
			quartzSchedulerManager.standby();
			return;
		}
	}

	@Produces
	@ApplicationScoped
	public StringEncrypter getStringEncrypter() {
		String encodeSalt = configurationFactory.getCryptoConfigurationSalt();

		if (StringHelper.isEmpty(encodeSalt)) {
			throw new ConfigurationException("Encode salt isn't defined");
		}

		try {
			StringEncrypter stringEncrypter = StringEncrypter.instance(encodeSalt);

			return stringEncrypter;
		} catch (EncryptionException ex) {
			throw new ConfigurationException("Failed to create StringEncrypter instance");
		}
	}

	public void initTimer() {
		this.isActive = new AtomicBoolean(false);
		this.setLastFinishedTime(System.currentTimeMillis());

		timerEvent.fire(new TimerEvent(new TimerSchedule(60, DEFAULT_INTERVAL), new AuthConfigurationEvent(),
				Scheduled.Literal.INSTANCE));
	}

	@Asynchronous
	public void reloadConfigurationTimerEvent(@Observes @Scheduled AuthConfigurationEvent authConfigurationEvent) {
		if (this.isActive.get()) {
			return;
		}

		if (!this.isActive.compareAndSet(false, true)) {
			return;
		}

		try {
			reloadConfiguration();
		} catch (Throwable ex) {
			log.error("Exception happened while reloading application configuration", ex);
		} finally {
			this.isActive.set(false);
			this.setLastFinishedTime(System.currentTimeMillis());
		}
	}

	private void reloadConfiguration() {
		PersistenceEntryManager localPersistenceEntryManager = persistenceEntryManagerInstance.get();
		log.trace("Attempting to use {}: {}", ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME, localPersistenceEntryManager.getOperationService());

		GluuConfiguration newConfiguration = loadConfiguration(localPersistenceEntryManager, "oxIDPAuthentication", "oxAuthenticationMode");

		List<GluuLdapConfiguration> newPersistenceAuthConfigs = loadPersistenceAuthConfigs(newConfiguration);

		if (!this.persistenceAuthConfigs.equals(newPersistenceAuthConfigs)) {
			recreatePersistenceAuthEntryManagers(newPersistenceAuthConfigs);
			this.persistenceAuthConfigs = newPersistenceAuthConfigs;

			event.select(ReloadAuthScript.Literal.INSTANCE)
					.fire(ExternalAuthenticationService.MODIFIED_INTERNAL_TYPES_EVENT_TYPE);
		}

		setDefaultAuthenticationMethod(newConfiguration);
	}

	/*
	 * Utility method which can be used in custom scripts
	 */
	public PersistenceEntryManager createPersistenceAuthEntryManager(GluuLdapConfiguration persistenceAuthConfig) {
		PersistenceEntryManagerFactory persistenceEntryManagerFactory = applicationFactory.getPersistenceEntryManagerFactory();
		Properties persistenceConnectionProperties = prepareAuthConnectionProperties(persistenceAuthConfig, persistenceEntryManagerFactory.getPersistenceType());

		PersistenceEntryManager persistenceAuthEntryManager = 
				persistenceEntryManagerFactory.createEntryManager(persistenceConnectionProperties);
		log.debug("Created custom authentication PersistenceEntryManager: {}", persistenceAuthEntryManager);

		externalPersistenceExtensionService.executePersistenceExtensionAfterCreate(persistenceConnectionProperties, persistenceAuthEntryManager);

		return persistenceAuthEntryManager;
	}

	protected Properties preparePersistanceProperties() {
		PersistenceConfiguration persistenceConfiguration = this.configurationFactory.getPersistenceConfiguration();
		FileConfiguration persistenceConfig = persistenceConfiguration.getConfiguration();
		Properties connectionProperties = (Properties) persistenceConfig.getProperties();

		EncryptionService securityService = encryptionServiceInstance.get();
		Properties decryptedConnectionProperties = securityService.decryptAllProperties(connectionProperties);
		return decryptedConnectionProperties;
	}

	protected Properties prepareCustomPersistanceProperties(String configId) {
		Properties connectionProperties = preparePersistanceProperties();
		if (StringHelper.isNotEmpty(configId)) {
			// Replace properties names 'configId.xyz' to 'configId.xyz' in order to
			// override default values
			connectionProperties = (Properties) connectionProperties.clone();

			String baseGroup = configId + ".";
			for (Object key : connectionProperties.keySet()) {
				String propertyName = (String) key;
				if (propertyName.startsWith(baseGroup)) {
					propertyName = propertyName.substring(baseGroup.length());

					Object value = connectionProperties.get(key);
					connectionProperties.put(propertyName, value);
				}
			}
		}

		return connectionProperties;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME)
	public PersistenceEntryManager createPersistenceEntryManager() {
		Properties connectionProperties = preparePersistanceProperties();

		PersistenceEntryManager persistenceEntryManager = applicationFactory.getPersistenceEntryManagerFactory()
				.createEntryManager(connectionProperties);
		log.info("Created {}: {} with operation service: {}",
				new Object[] { ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME, persistenceEntryManager,
						persistenceEntryManager.getOperationService() });

		externalPersistenceExtensionService.executePersistenceExtensionAfterCreate(connectionProperties, persistenceEntryManager);

		return persistenceEntryManager;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME)
	@ReportMetric
	public PersistenceEntryManager createMetricPersistenceEntryManager() {
		Properties connectionProperties = prepareCustomPersistanceProperties(
				ApplicationFactory.PERSISTENCE_METRIC_CONFIG_GROUP_NAME);

		PersistenceEntryManager persistenceEntryManager = applicationFactory.getPersistenceEntryManagerFactory()
				.createEntryManager(connectionProperties);
		log.info("Created {}: {} with operation service: {}",
				new Object[] { ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME, persistenceEntryManager,
						persistenceEntryManager.getOperationService() });

		externalPersistenceExtensionService.executePersistenceExtensionAfterCreate(connectionProperties, persistenceEntryManager);

		return persistenceEntryManager;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_AUTH_CONFIG_NAME)
	public List<GluuLdapConfiguration> createPersistenceAuthConfigs() {
		return persistenceAuthConfigs;
	}

	@Produces
	@ApplicationScoped
	@Named(ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME)
	public List<PersistenceEntryManager> createPersistenceAuthEntryManager() {
		List<PersistenceEntryManager> persistenceAuthEntryManagers = new ArrayList<PersistenceEntryManager>();
		if (this.persistenceAuthConfigs.size() == 0) {
			return persistenceAuthEntryManagers;
		}
		
		PersistenceEntryManagerFactory persistenceEntryManagerFactory = applicationFactory.getPersistenceEntryManagerFactory(LdapEntryManagerFactory.class);

		List<Properties> persistenceAuthProperties = prepareAuthConnectionProperties(this.persistenceAuthConfigs, persistenceEntryManagerFactory.getPersistenceType());
		log.trace("Attempting to create LDAP auth PersistenceEntryManager with properties: {}", persistenceAuthProperties);

		for (int i = 0; i < persistenceAuthProperties.size(); i++) {
			PersistenceEntryManager persistenceAuthEntryManager = 
					persistenceEntryManagerFactory.createEntryManager(persistenceAuthProperties.get(i));
			log.debug("Created {}#{}: {}", new Object[] { ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME, i,
					persistenceAuthEntryManager });

			persistenceAuthEntryManagers.add(persistenceAuthEntryManager);

			externalPersistenceExtensionService.executePersistenceExtensionAfterCreate(persistenceAuthProperties.get(i), persistenceAuthEntryManager);
		}

		return persistenceAuthEntryManagers;
	}

	public void recreatePersistenceEntryManager(@Observes @LdapConfigurationReload String event) {
		recreatePersistanceEntryManagerImpl(persistenceEntryManagerInstance,
				ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME);

		recreatePersistanceEntryManagerImpl(persistenceEntryManagerInstance,
				ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME, ReportMetric.Literal.INSTANCE);
	}

	protected void recreatePersistanceEntryManagerImpl(Instance<PersistenceEntryManager> instance,
			String persistenceEntryManagerName, Annotation... qualifiers) {
		// Get existing application scoped instance
		PersistenceEntryManager oldPersistenceEntryManager = CdiUtil.getContextBean(beanManager,
				PersistenceEntryManager.class, persistenceEntryManagerName);

		// Close existing connections
		closePersistenceEntryManager(oldPersistenceEntryManager, persistenceEntryManagerName);

		// Force to create new bean
		PersistenceEntryManager persistenceEntryManager = instance.get();
		instance.destroy(persistenceEntryManager);
		log.info("Recreated instance {}: {} with operation service: {}", persistenceEntryManagerName,
				persistenceEntryManager, persistenceEntryManager.getOperationService());
	}

	private void closePersistenceEntryManager(PersistenceEntryManager oldPersistenceEntryManager,
			String persistenceEntryManagerName) {
		// Close existing connections
		if ((oldPersistenceEntryManager != null) && (oldPersistenceEntryManager.getOperationService() != null)) {
			log.debug("Attempting to destroy {}:{} with operation service: {}", persistenceEntryManagerName,
					oldPersistenceEntryManager, oldPersistenceEntryManager.getOperationService());
			oldPersistenceEntryManager.destroy();
			log.debug("Destroyed {}:{} with operation service: {}", persistenceEntryManagerName,
					oldPersistenceEntryManager, oldPersistenceEntryManager.getOperationService());

			externalPersistenceExtensionService.executePersistenceExtensionAfterDestroy(oldPersistenceEntryManager);
		}
	}

	private void closePersistenceEntryManagers(List<PersistenceEntryManager> oldPersistenceEntryManagers) {
		// Close existing connections
		for (PersistenceEntryManager oldPersistenceEntryManager : oldPersistenceEntryManagers) {
			log.debug("Attempting to destroy {}: {}", ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME,
					oldPersistenceEntryManager);
			oldPersistenceEntryManager.destroy();
			log.debug("Destroyed {}: {}", ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME,
					oldPersistenceEntryManager);

			externalPersistenceExtensionService.executePersistenceExtensionAfterDestroy(oldPersistenceEntryManager);
		}
	}

	public void recreatePersistenceAuthEntryManagers(List<GluuLdapConfiguration> newPersistenceAuthConfigs) {
		// Get existing application scoped instance
		List<PersistenceEntryManager> oldPersistenceAuthEntryManagers = CdiUtil.getContextBean(beanManager,
				new ParameterizedTypeImpl(List.class, PersistenceEntryManager.class),
				ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME);

		// Recreate components
		this.persistenceAuthConfigs = newPersistenceAuthConfigs;

		// Close existing connections
		closePersistenceEntryManagers(oldPersistenceAuthEntryManagers);

		// Destroy old Ldap auth entry managers
		for (PersistenceEntryManager oldPersistenceAuthEntryManager : oldPersistenceAuthEntryManagers) {
			log.debug("Attempting to destroy {}: {}", ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME,
					oldPersistenceAuthEntryManager);
			oldPersistenceAuthEntryManager.destroy();
			log.debug("Destroyed {}: {}", ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME,
					oldPersistenceAuthEntryManager);

			externalPersistenceExtensionService.executePersistenceExtensionAfterDestroy(oldPersistenceAuthEntryManager);
		}

		// Force to create new Ldap auth entry managers bean
		List<PersistenceEntryManager> persistenceAuthEntryManagers = persistenceAuthEntryManagerInstance.get();
		persistenceAuthEntryManagerInstance.destroy(persistenceAuthEntryManagers);
		log.info("Recreated instance {}: {}", ApplicationFactory.PERSISTENCE_AUTH_ENTRY_MANAGER_NAME,
				persistenceAuthEntryManagers);

		// Force to create new auth configuration bean
		List<GluuLdapConfiguration> oldPersistenceAuthConfigs = persistenceAuthConfigInstance.get();
		persistenceAuthConfigInstance.destroy(oldPersistenceAuthConfigs);
	}

	private List<Properties> prepareAuthConnectionProperties(List<GluuLdapConfiguration> persistenceAuthConfigs, String persistenceType) {
		List<Properties> result = new ArrayList<Properties>();

		// Prepare connection providers per LDAP authentication configuration
		for (GluuLdapConfiguration persistenceAuthConfig : persistenceAuthConfigs) {
			Properties decrypytedConnectionProperties = prepareAuthConnectionProperties(persistenceAuthConfig, persistenceType);

			result.add(decrypytedConnectionProperties);
		}

		return result;
	}

	private Properties prepareAuthConnectionProperties(GluuLdapConfiguration persistenceAuthConfig, String persistenceType) {
		String prefix = persistenceType + "#";
		FileConfiguration configuration = configurationFactory.getPersistenceConfiguration().getConfiguration();

		Properties properties = (Properties) configuration.getProperties().clone();
		if (persistenceAuthConfig != null) {
			properties.setProperty(prefix + "servers", buildServersString(persistenceAuthConfig.getServers()));

			String bindDn = persistenceAuthConfig.getBindDN();
			if (StringHelper.isNotEmpty(bindDn)) {
				properties.setProperty(prefix + "bindDN", bindDn);
				properties.setProperty(prefix + "bindPassword", persistenceAuthConfig.getBindPassword());
			}
			properties.setProperty(prefix + "useSSL", Boolean.toString(persistenceAuthConfig.isUseSSL()));
			properties.setProperty(prefix + "maxconnections", Integer.toString(persistenceAuthConfig.getMaxConnections()));
			
			// Remove internal DB trustStoreFile property
			properties.remove(prefix + "ssl.trustStoreFile");			
			properties.remove(prefix + "ssl.trustStorePin");			
			properties.remove(prefix + "ssl.trustStoreFormat");			
		}

		EncryptionService securityService = encryptionServiceInstance.get();
		Properties decrypytedProperties = securityService.decryptAllProperties(properties);

		return decrypytedProperties;
	}

	private String buildServersString(List<?> servers) {
		StringBuilder sb = new StringBuilder();

		if (servers == null) {
			return sb.toString();
		}

		boolean first = true;
		for (Object server : servers) {
			if (first) {
				first = false;
			} else {
				sb.append(",");
			}

			if (server instanceof SimpleProperty) {
				sb.append(((SimpleProperty) server).getValue());
			} else {
				sb.append(server);
			}
		}

		return sb.toString();
	}

	private void setDefaultAuthenticationMethod(GluuConfiguration configuration) {
		String currentAuthMethod = null;
		if (this.authenticationMode != null) {
			currentAuthMethod = this.authenticationMode.getName();
		}

		String actualAuthMethod = getActualDefaultAuthenticationMethod(configuration);

		if (!StringHelper.equals(currentAuthMethod, actualAuthMethod)) {
			authenticationMode = null;
			if (actualAuthMethod != null) {
				this.authenticationMode = new AuthenticationMode(actualAuthMethod);
			}

			authenticationModeInstance.destroy(authenticationModeInstance.get());
		}
	}

	private String getActualDefaultAuthenticationMethod(GluuConfiguration configuration) {
		if ((configuration != null) && (configuration.getAuthenticationMode() != null)) {
			return configuration.getAuthenticationMode();
		}
		
		CustomScriptConfiguration defaultExternalAuthenticator = externalAuthenticationService.getDefaultExternalAuthenticator(AuthenticationScriptUsageType.INTERACTIVE);
		if (defaultExternalAuthenticator != null) {
			return defaultExternalAuthenticator.getName();
		}

		return OxConstants.SCRIPT_TYPE_INTERNAL_RESERVED_NAME;
	}

	@Produces
	@ApplicationScoped
	public AuthenticationMode getDefaultAuthenticationMode() {
		return authenticationMode;
	}

	private GluuConfiguration loadConfiguration(PersistenceEntryManager localPersistenceEntryManager,
			String... persistenceReturnAttributes) {
		String configurationDn = configurationFactory.getBaseDn().getConfiguration();
		if (StringHelper.isEmpty(configurationDn)) {
			return null;
		}

		GluuConfiguration configuration = null;
		try {
			configuration = localPersistenceEntryManager.find(configurationDn, GluuConfiguration.class,
					persistenceReturnAttributes);
		} catch (BasePersistenceException ex) {
			log.error("Failed to load global configuration entry from Ldap", ex);
			return null;
		}

		return configuration;
	}

	private List<GluuLdapConfiguration> loadPersistenceAuthConfigs(GluuConfiguration configuration) {
		List<GluuLdapConfiguration> persistenceAuthConfigs = new ArrayList<GluuLdapConfiguration>();

		List<oxIDPAuthConf> persistenceIdpAuthConfigs = loadLdapIdpAuthConfigs(configuration);
		if (persistenceIdpAuthConfigs == null) {
			return persistenceAuthConfigs;
		}

		for (oxIDPAuthConf persistenceIdpAuthConfig : persistenceIdpAuthConfigs) {
			GluuLdapConfiguration persistenceAuthConfig = persistenceIdpAuthConfig.getConfig();
			if ((persistenceAuthConfig != null) && persistenceAuthConfig.isEnabled()) {
				persistenceAuthConfigs.add(persistenceAuthConfig);
			}
		}

		return persistenceAuthConfigs;
	}

	private List<oxIDPAuthConf> loadLdapIdpAuthConfigs(GluuConfiguration configuration) {
		if ((configuration == null) || (configuration.getOxIDPAuthentication() == null)) {
			return null;
		}

		List<oxIDPAuthConf> configurations = new ArrayList<oxIDPAuthConf>();
		for (oxIDPAuthConf authConf : configuration.getOxIDPAuthentication()) {
			if (authConf.getType().equalsIgnoreCase("ldap") || authConf.getType().equalsIgnoreCase("auth")) {
				configurations.add(authConf);
			}
		}

		return configurations;
	}

	public void destroy(@Observes @BeforeDestroyed(ApplicationScoped.class) ServletContext init) {
		log.info("Stopping services and closing DB connections at server shutdown...");
		log.debug("Checking who intiated destory", new Throwable());

		metricService.close();

		PersistenceEntryManager persistenceEntryManager = persistenceEntryManagerInstance.get();
		closePersistenceEntryManager(persistenceEntryManager, ApplicationFactory.PERSISTENCE_ENTRY_MANAGER_NAME);

		List<PersistenceEntryManager> persistenceAuthEntryManagers = persistenceAuthEntryManagerInstance.get();
		closePersistenceEntryManagers(persistenceAuthEntryManagers);
	}

	public long getLastFinishedTime() {
		return lastFinishedTime;
	}

	public void setLastFinishedTime(long lastFinishedTime) {
		this.lastFinishedTime = lastFinishedTime;
	}

	/**
	 * Method to initialize CIBA requests processor job according to a json property which
	 * should be more than 0 seconds of interval
	 */
	private void initCibaRequestsProcessor() {
		if (appConfiguration.getCibaEnabled() && appConfiguration.getBackchannelRequestsProcessorJobIntervalSec() > 0) {
			if (cibaRequestsProcessorJob != null) {
				cibaRequestsProcessorJob.initTimer();
			}
		} else {
			log.warn("Ciba requests processor hasn't been started because the interval is not valid to run or this is disabled, value: {}",
					appConfiguration.getBackchannelRequestsProcessorJobIntervalSec());
		}
	}

}
