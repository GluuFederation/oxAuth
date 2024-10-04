# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2023, Gluu
#
# Author: Yuriy Movchan
# Updated by: Aliaksander Samuseu
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.util import StringHelper

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType

import sys
import json

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "SAML 2 OIDC ACR router script. Initialization"

        if not configurationAttributes.containsKey("entityid_oidc_acr_map_file"):
            print "SAML 2 OIDC ACR router script. Initialization. Property entityid_oidc_acr_map_file is mandatory, but it's missing. Aborting initialization..."
            return False
        else:
            entityidOidcAcrMapFile = configurationAttributes.get("entityid_oidc_acr_map_file").getValue2()
            mappings_dict = self.loadEntityidOidcAcrMap(entityidOidcAcrMapFile)
            if (not mappings_dict):
                print "SAML 2 OIDC ACR router script. File with SAML entityIds to OIDC ACR mappings must not be empty. Aborting initialization..."
                return False
            else:
                self.entityidOidcAcrMap = mappings_dict["mappings"]
                self.default_acr = mappings_dict["default"]
                print "Loaded mapping configuration is:"
                print "SAML 2 OIDC ACR mappings: %s" % (self.entityidOidcAcrMap)
                print "Default OIDC ACR: %s" % (self.default_acr)


        print "SAML 2 OIDC ACR router script. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "SAML 2 OIDC ACR router script. Destroy"
        print "SAML 2 OIDC ACR router script. Destroyed successfully"

        return True
        
    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getApiVersion(self):
        return 11

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return False

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        #print "DEBUG OUTPUT: SAML 2 OIDC ACR router script. Processing url query arguments..."
        # !!!Note: oxAuth stores in session only known parameters
        # We need to add to authorizationRequestCustomAllowedParameters oxAuth property issuerId and entityId

        identity = CdiUtil.bean(Identity)
        identity.getSessionId().getSessionAttributes()

        session_attributes = identity.getSessionId().getSessionAttributes()
        if session_attributes.containsKey("issuerId") and session_attributes.containsKey("entityId"):

            issuerId = session_attributes.get("issuerId")
            entityId = session_attributes.get("entityId")
            redirect_uri = session_attributes.get("redirect_uri")
            #print "DEBUG OUTPUT: SAML 2 OIDC ACR router script. issuerId: %s, entityId: %s, redirect_uri: %s: " % (issuerId, entityId, redirect_uri)
	    if entityId in self.entityidOidcAcrMap:
		target_oidc_acr = self.entityidOidcAcrMap[entityId]
		print "SAML 2 OIDC ACR router script. Next target OIDC ACR is chosen based on SP entityId %s: %s" % (entityId, target_oidc_acr)
		return target_oidc_acr
	    else:
		print "SAML 2 OIDC ACR router script. No mapping for entityId %s is found, redirecting to the default method" % (entityId)
		return self.default_acr
	else:
	    print "SAML 2 OIDC ACR router script. entityId url query parameter must be present in case of valid Shibboleth IDP authentication flow, but it's not found. Aborting the flow..."
	    return False


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

    def loadEntityidOidcAcrMap(self, entityidOidcAcrMapFile):
        entityidOidcAcrMap = None

        # Load authentication configuration from file
        f = open(entityidOidcAcrMapFile, 'r')
        try:
            entityidOidcAcrMap = json.loads(f.read())
        except:
            print "SAML 2 OIDC ACR router script. Loading entityId to OIDC ACR mappings. Failed to load the mappings from file %s" % (entityidOidcAcrMapFile)
            return None
        finally:
            f.close()

        return entityidOidcAcrMap
