# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
# Modify: Mostafejur Rahman

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import AuthenticationService
from org.gluu.util import StringHelper

from java.util import Arrays

import java
import json


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print("Initialization")
        self.language_file = None
        self.isLanguageFile = self.initiateLanguageFile(configurationAttributes)
        print("Initialized successfully")
        return True

    def destroy(self, configurationAttributes):
        print("Destroy")
        print("Destroyed successfully")
        return True

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getApiVersion(self):
        return 11

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        authenticationService = CdiUtil.bean(AuthenticationService)

        if (step == 1):
            print("Authenticate for step 1")

            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()

            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            logged_in = False
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                logged_in = authenticationService.authenticate(user_name, user_password)

            if (not logged_in):
                self.prepareForStep(configurationAttributes, requestParameters, step)
                return False

            return True
        else:
            self.prepareForStep(configurationAttributes, requestParameters, step)
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print("Prepare for Step 1")
            identity = CdiUtil.bean(Identity);
            if self.isLanguageFile:
                identity.setWorkingParameter("language_file", self.language_file);
                print("Working parameter set successfully for view rendering")

            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("language_file")

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return "/auth/customLanguage/login.xhtml"

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print("Get external logout URL call")
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True

    def initiateLanguageFile(self, configurationAttributes):
        print("Initialize of Language file")
        if not configurationAttributes.containsKey("language_file"):
            return False

        language_file = configurationAttributes.get("language_file").getValue2()

        print("Load language from file")
        f = open(language_file, 'r')
        try:
            languageFileObject = json.loads(f.read())
        except:
            print("Initialize language file. Failed to load language from file: %s" % language_file)
            return False
        finally:
            f.close()

        self.language_file = languageFileObject
        print("Initialization language file configured correctly")

        return True