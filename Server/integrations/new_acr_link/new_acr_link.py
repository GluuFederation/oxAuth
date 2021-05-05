# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Christian Eland
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import AuthenticationService
from org.gluu.util import StringHelper
from urlparse import urlparse, parse_qsl, urlunparse
from urllib import urlencode
from javax.faces.context import FacesContext

import java

class Utils():
    
    def getNewAcrValuesUrl(self, new_acr_values):
        ''' Generates authz request url link with new acr_values
        Args:
            new_acr_values (str): the desired new acr_values
        Returns:
            str: authz url with new `acr_values`
        '''

        facesContext = CdiUtil.bean(FacesContext)
        authenticationService = CdiUtil.bean(AuthenticationService)

        parameters_as_string = authenticationService.parametersAsString()
        scheme = facesContext.getExternalContext().getRequest().getScheme()
        server_name = facesContext.getExternalContext().getRequest().getServerName()

        url_object = urlparse(
            '%s://%s/oxauth/authorize.htm?%s' % (
            scheme, server_name, parameters_as_string) 
            )
        query_dict = dict(parse_qsl(url_object.query))
        query_dict["acr_values"] = new_acr_values
        new_query_string = urlencode(query_dict)
        new_url_link= urlunparse([
            url_object.scheme, url_object.netloc, url_object.path,
            url_object.params, new_query_string, url_object.fragment
            ])
        return new_url_link


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.utils = Utils()

    def init(self, customScript,  configurationAttributes):
        print "New Acr Link. Initialization"
        print "New Acr Link. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "New Acr Link. Destroy"
        print "New Acr Link. Destroyed successfully"
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
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()

        if (step == 1):
            print "New Acr Link. Authenticate for step 1"

            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()

            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            logged_in = False
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                logged_in = authenticationService.authenticate(user_name, user_password)

            if (not logged_in):
                return False

            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "New Acr Link. Prepare for step %s" % step
        if (step == 1):

            identity = CdiUtil.bean(Identity)

            # Fetch NEW_ACR_VALUES from custom script attribute and setWorkingParameters
            for item in configurationAttributes:
                if item.startswith('new_acr_values'):
                    acr_values = configurationAttributes.get(item).getValue2()
                    new_authz_request_link = self.utils.getNewAcrValuesUrl(acr_values)
                    print "New Acr Link. Setting working parameter for item %s with value %s"  % (
                        item, new_authz_request_link
                    )
                    identity.setWorkingParameter(item, new_authz_request_link)
                if not item.startswith("new_acr_values"):
                    text = configurationAttributes.get(item).getValue2()
                    print "New Acr Link. Setting working parameter for item %s with text %s"  % (
                        item, text
                    )
                    identity.setWorkingParameter(item, text)
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        print "New Acr Link. entered getPageForStep - step %s" % step
        if step == 1:
            print "New Acr Link. returning custom login.xhtml"
            return "/auth/new_acr_link/login.xhtml"

        return ""


    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True
