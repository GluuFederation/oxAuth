# oxShibboleth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2022, Gluu
#
# Author: Djeumen Rolain
#

from org.gluu.model.custom.script.type.idp import IdpType
from org.gluu.util import StringHelper
from org.gluu.idp.externalauth import AuthenticatedNameTranslator
from org.gluu.idp.externalauth import ShibOxAuthAuthServlet
from net.shibboleth.idp.authn.principal import UsernamePrincipal, IdPAttributePrincipal
from net.shibboleth.idp.authn import ExternalAuthentication
from net.shibboleth.idp.attribute import IdPAttribute, StringAttributeValue
from net.shibboleth.idp.authn.context import AuthenticationContext, ExternalAuthenticationContext
from net.shibboleth.idp.attribute.context import AttributeContext
from javax.security.auth import Subject
from java.util import Collections, HashMap, HashSet, ArrayList, Arrays

import java

class IdpExtension(IdpType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Idp extension. Initialization"
        
        self.defaultNameTranslator = AuthenticatedNameTranslator()

        self.allowedAcrsList = ArrayList()
        if configurationAttributes.containsKey("allowed_acrs"):
            allowed_acrs = configurationAttributes.get("allowed_acrs").getValue2()
            allowed_acrs_list_array = StringHelper.split(allowed_acrs, ",")
            self.allowedAcrsList = Arrays.asList(allowed_acrs_list_array)

        self.sourceAttr = None
        self.targetAttr = None

        if configurationAttributes.containsKey("saml_source_attribute"):
            self.sourceAttr = configurationAttributes.get("saml_source_attribute").getValue2()
        
        if configurationAttributes.containsKey("saml_target_attribute"):
            self.targetAttr = configurationAttributes.get("saml_target_attribute").getValue2()

        if self.sourceAttr is None or self.targetAttr is None:
            print "Init Warning. Missing script configuration property: saml_source_attribute or saml_target_attribute"
        else:
            print "Idp extension. saml_source_attribute => %s , saml_target_attribute => %s" % (self.sourceAttr,self.targetAttr)
        

        print "Idp extension. Initialization. The property allowed_acrs is %s" % self.allowedAcrsList
        
        return True

    def destroy(self, configurationAttributes):
        print "Idp extension. Destroy"
        return True

    def getApiVersion(self):
        return 13

    # Translate attributes from user profile
    #   context is org.gluu.idp.externalauth.TranslateAttributesContext (https://github.com/GluuFederation/shib-oxauth-authn3/blob/master/src/main/java/org/gluu/idp/externalauth/TranslateAttributesContext.java)
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def translateAttributes(self, context, configurationAttributes):
        print "Idp extension. Method: translateAttributes"
        userProfile = context.getUserProfile()
        if userProfile is None:
           print "No valid user profile could be found to translate"
           return False
          
        if userProfile.getId() is None:
           print "No valid user principal could be found to traslate"
           return False
        
        self.defaultNameTranslator.populateIdpAttributeList(userProfile.getAttributes(),context)
        
        #Return True to specify that default method is not needed
        return True

    # Update attributes before releasing them
    #   context is org.gluu.idp.consent.processor.PostProcessAttributesContext (https://github.com/GluuFederation/shib-oxauth-authn3/blob/master/src/main/java/org/gluu/idp/consent/processor/PostProcessAttributesContext.java)
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def updateAttributes(self, context, configurationAttributes):
        print "Idp extension. Method: updateAttributes"
        if self.sourceAttr is None or self.targetAttr is None:
            return True 
        sourceIdpAttr = context.getIdpAttributeMap().get(self.sourceAttr)
        if sourceIdpAttr is not None:
            context.getIdpAttributeMap().remove(self.sourceAttr)
            targetIdpAttr = IdPAttribute(self.targetAttr)
            targetIdpAttr.setValues(sourceIdpAttr.getValues())
            context.getIdpAttributeMap().put(self.targetAttr,targetIdpAttr)
        
        return True

    # Check before allowing user to log in
    #   context is org.gluu.idp.externalauth.PostAuthenticationContext (https://github.com/GluuFederation/shib-oxauth-authn3/blob/master/src/main/java/org/gluu/idp/externalauth/PostAuthenticationContext.java)
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def postAuthentication(self, context, configurationAttributes):
        print "Idp extension. Method: postAuthentication"
        userProfile = context.getUserProfile()
        authenticationContext = context.getAuthenticationContext
        
        requestedAcr = None
        if authenticationContext != None:
            requestedAcr = authenticationContext.getAuthenticationStateMap().get(org.gluu.idp.externalauth.OXAUTH_ACR_REQUESTED)

        usedAcr = userProfile.getUsedAcr()

        print "Idp extension. Method: postAuthentication. requestedAcr = %s, usedAcr = %s" % (requestedAcr, usedAcr)

        if requestedAcr == None:
            print "Idp extension. Method: postAuthentication. requestedAcr is not specified"
            return True

        if not self.allowedAcrsList.contains(usedAcr):
            print "Idp extension. Method: postAuthentication. usedAcr '%s' is not allowed" % usedAcr
            return False

        return True

    # Check before allowing user to log in
    #   context is org.gluu.idp.externalauth.PostAuthenticationContext (https://github.com/GluuFederation/shib-oxauth-authn3/blob/master/src/main/java/org/gluu/idp/externalauth/PostAuthenticationContext.java)
    #   configurationAttributes is java.util.Map<String, SimpleCustomProperty>
    def postAuthentication(self, context, configurationAttributes):
        print "Idp extension. Method: postAuthentication"
        userProfile = context.getUserProfile()
        authenticationContext = context.getAuthenticationContext()
        
        requestedAcr = None
        if authenticationContext != None:
            requestedAcr = authenticationContext.getAuthenticationStateMap().get(ShibOxAuthAuthServlet.OXAUTH_ACR_REQUESTED)

        usedAcr = userProfile.getUsedAcr()

        print "Idp extension. Method: postAuthentication. requestedAcr = %s, usedAcr = %s" % (requestedAcr, usedAcr)

        if requestedAcr == None:
            print "Idp extension. Method: postAuthentication. requestedAcr is not specified"
            return True

        if not self.allowedAcrsList.contains(usedAcr):
            print "Idp extension. Method: postAuthentication. usedAcr '%s' is not allowed" % usedAcr
            return False

        return True
