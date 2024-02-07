# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2023, Gluu
#
# Author: Yuriy Movchan
#
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.util import StringHelper

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "ACR SAML Router. Initialization"
        print "ACR SAML Router. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "ACR SAML Router. Destroy"
        print "ACR SAML Router. Destroyed successfully"

        return True
        
    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getApiVersion(self):
        return 11

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return False

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "ACR SAML Router. Get new acr value"
        # !!!Note: oxAuth stores in session only known parameters
        # We need to add to authorizationRequestCustomAllowedParameters oxAuth property issuerId and entityId

        identity = CdiUtil.bean(Identity)
        identity.getSessionId().getSessionAttributes()

        session_attributes = identity.getSessionId().getSessionAttributes()
        if session_attributes.containsKey("issuerId") and session_attributes.containsKey("entityId"):

            issuerId = session_attributes.get("issuerId")
            entityId = session_attributes.get("entityId")
            redirect_uri = session_attributes.get("redirect_uri")
            print "ACR SAML Router. issuerId: %s, entityId: %s, redirect_uri: %s: " % (issuerId, entityId, redirect_uri)
            if StringHelper.equalsIgnoreCase(issuerId, "https://samltest.id/saml/sp"):
                print "ACR SAML Router. Redirect to super_gluu"
                return "super_gluu"

        print "ACR SAML Router. Redirect to default method"
        return "basic"

    def authenticate(self, configurationAttributes, requestParameters, step):
        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        return True

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return ""

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True
