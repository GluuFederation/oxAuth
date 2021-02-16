# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2017, Gluu
#
# Author: Madhumita S
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.authz import ConsentGatheringType
from org.gluu.util import StringHelper
from org.gluu.jsf2.service import FacesService
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.util import ServerUtil

import java
import random

class ConsentGathering(ConsentGatheringType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
    
    	if (not configurationAttributes.containsKey("third_party_URL")):
	        print "Consent-Gathering. - Thirdparty URL. Initialization. Property third_party_URL is not specified"
	        return False
        else: 
        	self.third_party_URL = configurationAttributes.get("third_party_URL").getValue2() 
        	
        print "Consent-Gathering. Initializing ..."
        print "Consent-Gathering. Initialized successfully"

        return True

    def destroy(self, configurationAttributes):
        print "Consent-Gathering. Destroying ..."
        print "Consent-Gathering. Destroyed successfully"

        return True

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getApiVersion(self):
        return 11

    # Main consent-gather method. Must return True (if gathering performed successfully) or False (if fail).
    # All user entered values can be access via Map<String, String> context.getPageAttributes()
	# context is reference of org.gluu.oxauth.service.external.context.ConsentGatheringContext
    def authorize(self, step, context): 
        print "Consent-Gathering. Authorizing... %s " % step

        allow =  ServerUtil.getFirstValue(context.getRequestParameters(), "allow") 
        print "allow : %s " % allow
        if (allow is not None) and (allow == "true"):
                print "Consent-Gathering. Authorization success for step 1"
                return True
		else:
				print "Consent-Gathering. Authorization declined for step 1"
				return False
				

    def getNextStep(self, step, context):
        return -1

    def prepareForStep(self, step, context):
        print "Consent-Gathering. prepare for step... %s" % step 

        if not context.isAuthenticated():
            print "User is not authenticated. Aborting authorization flow ..."
            return False

		print "Consent-Gathering. Redirecting to ... %s " % self.third_party_URL
        facesService = CdiUtil.bean(FacesService)
        facesService.redirectToExternalURL(self.third_party_URL )
        return True

    def getStepsCount(self, context):
        return 1

    def getPageForStep(self, step, context):
        print "Consent-Gathering. getPageForStep... %s" % step
        if step == 1:
            return "/authz/redirect.xhtml"
        
        return ""
