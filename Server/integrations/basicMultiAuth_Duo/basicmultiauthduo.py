# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2018, Gluu
#
# Author: Yuriy Movchan
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import UserService, AuthenticationService, AppInitializer
from org.gluu.util import ArrayHelper, StringHelper
from java.util import ArrayList, Arrays, Properties
from org.gluu.util import StringHelper


import java
import json

from BasicMultiAuthConfExternalAuthenticator import PersonAuthentication as BasicMultiAuthConfExternalAuthenticator
from DuoExternalAuthenticator import PersonAuthentication as DuoExternalAuthenticator

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

        self.basicmultiauthconfExternalAuthenticator = BasicMultiAuthConfExternalAuthenticator(currentTimeMillis)
        self.duoExternalAuthenticator = DuoExternalAuthenticator(currentTimeMillis)

    def init(self, customScript, configurationAttributes):
        print "BasicMultiAuth + Duo. Initialization"
        
        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.init(None, configurationAttributes)
        duo_result = self.duoExternalAuthenticator.init(None, configurationAttributes)

        print "BasicMultiAuth + Duo. Initialized successfully"

        return basicmultiauth_result and duo_result

    def destroy(self, configurationAttributes):
        print "BasicMultiAuth + Duo. Destroy"

        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.destroy(configurationAttributes)
        duo_result = self.duoExternalAuthenticator.destroy(configurationAttributes)

        print "BasicMultiAuth + Duo. Destroyed successfully"

        return basicmultiauth_result and duo_result

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.isValidAuthenticationMethod(usageType, configurationAttributes)
        duo_result = self.duoExternalAuthenticator.isValidAuthenticationMethod(usageType, configurationAttributes)

        return basicmultiauth_result and duo_result

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.getAlternativeAuthenticationMethod(usageType, configurationAttributes)
        if basicmultiauth_result != None:
            return basicmultiauth_result

        duo_result = self.duoExternalAuthenticator.getAlternativeAuthenticationMethod(usageType, configurationAttributes)
        if duo_result != None:
            return duo_result

        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        result = False

        start_duo = False
        if step == 1:
            # Execute Basic Multi Auth for step #1
            result = self.basicmultiauthconfExternalAuthenticator.authenticate(configurationAttributes, requestParameters, step)
            if result:
                # Instruct oxAuth to store user in session in varible auth_user
                identity = CdiUtil.bean(Identity)
                authenticationService = CdiUtil.bean(AuthenticationService)
                authenticationService.authenticate(identity.getUser().getUserId())

                # Execute Basic Multi Auth for step #1
                result = result and self.duoExternalAuthenticator.authenticate(configurationAttributes, requestParameters, step)
        elif step == 2:
            # Execute DUO for step #1 if needed
            duo_count_steps = self.duoExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
            if duo_count_steps == 2:
                result = self.duoExternalAuthenticator.authenticate(configurationAttributes, requestParameters, step)
        elif step == 3:
            # Execute DUO for step #2 if needed
            duo_count_steps = self.duoExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
            if duo_count_steps == 2:
                result = self.duoExternalAuthenticator.authenticate(configurationAttributes, requestParameters, 2)

        return result

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        result = False

        # Execute Basic Multi Auth for step #1
        if step == 1:
            # Execute Basic Multi Auth for step #1
            print "Executing Basic Multi Auth for step #1....."
            result = self.basicmultiauthconfExternalAuthenticator.prepareForStep(configurationAttributes, requestParameters, step)
            if result:
                result = self.duoExternalAuthenticator.prepareForStep(configurationAttributes, requestParameters, step)
        elif step == 2:
            # Execute DUO for step #2 if needed
            print "Execute DUO for step #2 if needed elif thingy...."
            duo_count_steps = self.duoExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
            if duo_count_steps == 2:
                print "Started executing Duo for step #2..."
                result = self.duoExternalAuthenticator.prepareForStep(configurationAttributes, requestParameters, step)
                print "Completed executing Duo for step #2..."
        elif step == 3:
            # Execute DUO for step #3 if needed
            print "Execute DUO for step #3 if needed elif thingy...."
            duo_count_steps = self.duoExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
            if duo_count_steps == 2:
                print "Started executing Duo for step #3..."
                result = self.duoExternalAuthenticator.prepareForStep(configurationAttributes, requestParameters, 2)
                print "Execute DUO for step #2 if needed if thingy thingy completed"

        return result

    def getExtraParametersForStep(self, configurationAttributes, step):
        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.getExtraParametersForStep(configurationAttributes, step)
        duo_result = self.duoExternalAuthenticator.getExtraParametersForStep(configurationAttributes, step)
        
        if basicmultiauth_result == None:
            return duo_result

        if duo_result == None:
            return basicmultiauth_result
        
        result_list = ArrayList()
        result_list.addAll(basicmultiauth_result)
        result_list.addAll(duo_result)

        return result_list

    def getCountAuthenticationSteps(self, configurationAttributes):
        basicmultiauth_count_steps = self.basicmultiauthconfExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
        duo_count_steps = self.duoExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
        print "BasicMultiAuth + Duo. Get count authentication steps. basicmultiauth_count_steps = %s, duo_count_steps = %s" % (basicmultiauth_count_steps, duo_count_steps)

        if (basicmultiauth_count_steps == 1) and (duo_count_steps == 1):
            return 1

        if (basicmultiauth_count_steps == 2) and (duo_count_steps == 2):
            return 3

        return max(basicmultiauth_count_steps, duo_count_steps)

    def getPageForStep(self, configurationAttributes, step):
        result = ""

        if step == 1:
            result = self.basicmultiauthconfExternalAuthenticator.getPageForStep(configurationAttributes, step)
        elif step == 2:
            basicmultiauth_count_steps = self.basicmultiauthconfExternalAuthenticator.getCountAuthenticationSteps(configurationAttributes)
            if basicmultiauth_count_steps == 2:
                result = self.basicmultiauthconfExternalAuthenticator.getPageForStep(configurationAttributes, step)
            else:
                result = self.duoExternalAuthenticator.getPageForStep(configurationAttributes, step)
        elif step == 3:
            result = self.duoExternalAuthenticator.getPageForStep(configurationAttributes, step)

        return result

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        basicmultiauth_result = self.basicmultiauthconfExternalAuthenticator.logout(configurationAttributes, requestParameters)
        duo_result = self.duoExternalAuthenticator.logout(configurationAttributes, requestParameters)

        return basicmultiauth_result and duo_result
