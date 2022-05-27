# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2022, Gluu
#
# Author: Yuriy Movchan
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import UserService, AuthenticationService, AppInitializer
from org.gluu.oxauth.service.common import ApplicationFactory
from org.gluu.oxauth.service import MetricService
from org.gluu.oxauth.service.common import EncryptionService
from org.gluu.model.metric import MetricType
from org.gluu.util import StringHelper
from org.gluu.util import ArrayHelper
from org.gluu.persist.service import PersistanceFactoryService
from org.gluu.persist.ldap.impl import LdapEntryManagerFactory
from org.gluu.model.ldap import GluuLdapConfiguration
from java.util import List, Arrays, Properties

import java

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Basic (ldap auth conf). Initialization"

        authenticationService = CdiUtil.bean(AuthenticationService)
        self.ldapAuthConfigs = authenticationService.getLdapAuthConfigs()
        self.ldapAuthEntryManagers = authenticationService.getLdapAuthEntryManagers()
        if self.ldapAuthEntryManagers == None:
            print "Basic (ldap auth conf). At least one LDAP authentication configuration should be defined"
            return False

        print "Basic (ldap auth conf). Found %s LDAP Authentication entry managers" % self.ldapAuthEntryManagers.size()

        print "Basic (ldap auth conf). Initialized successfully"
        return True

    def destroy(self, authConfiguration):
        print "Basic (ldap auth conf). Destroy"

        print "Basic (ldap auth conf). Destroyed successfully"

        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        authenticationService = CdiUtil.bean(AuthenticationService)

        if (step == 1):
            print "Basic (ldap auth conf). Authenticate for step 1"

            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()

            metricService = CdiUtil.bean(MetricService)
            timerContext = metricService.getTimer(MetricType.OXAUTH_USER_AUTHENTICATION_RATE).time()
            try:
                keyValue = credentials.getUsername()
                userPassword = credentials.getPassword()
    
                if (StringHelper.isNotEmptyString(keyValue) and StringHelper.isNotEmptyString(userPassword)):
                    for i in range(self.ldapAuthEntryManagers.size()):
                        ldapConfiguration = self.ldapAuthConfigs.get(i)
                        ldapEntryManager = self.ldapAuthEntryManagers.get(i)

                        primaryKey = ldapConfiguration.getPrimaryKey()
                        localPrimaryKey = ldapConfiguration.getLocalPrimaryKey()
    
                        print "Basic (ldap auth conf). Authenticate for step 1. Using configuration: " + ldapConfiguration.getConfigId()
    

                        loggedIn = authenticationService.authenticate(ldapConfiguration, ldapEntryManager, keyValue, userPassword, primaryKey, localPrimaryKey)
                        if (loggedIn):
                            metricService.incCounter(MetricType.OXAUTH_USER_AUTHENTICATION_SUCCESS)
                            return True
            finally:
                timerContext.stop()
                
            metricService.incCounter(MetricType.OXAUTH_USER_AUTHENTICATION_FAILURES)

            return False
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic (ldap auth conf). Prepare for Step 1"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return ""

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True
