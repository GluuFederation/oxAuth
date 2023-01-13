# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
# Modified: Mobarak Hosen Shakil
# 

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import AuthenticationService
from org.gluu.util import StringHelper
from javax.faces.context import FacesContext
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service.common import UserService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service.common import EncryptionService
from java.util import Arrays
from org.gluu.oxauth.util import CertUtil
from org.gluu.oxauth.model.util import CertUtils
from org.gluu.oxauth.service.net import HttpService
from org.apache.http.params import CoreConnectionPNames

import sys
import base64
import urllib
import json
import java

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript,  configurationAttributes):
        print "Basic. Initialized successfully"

        self.enabled_recaptcha = self.initRecaptcha(configurationAttributes)
        print "Basic. Initialization. enabled_recaptcha: '%s'" % self.enabled_recaptcha

        print "Basic. Initialized successfully"
        return True
    
    def destroy(self, configurationAttributes):
        print "Basic. Destroy"
        print "Basic. Destroyed successfully"
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
        print "Basic. Authenticate for step 1"

        authenticationService = CdiUtil.bean(AuthenticationService)

        if step == 1:

            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()

            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            logged_in = False
            #self.enabled_recaptcha = self.initRecaptcha(configurationAttributes)
            #self.prepareForStep(configurationAttributes, requestParameters, step)
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                if self.enabled_recaptcha:
                    print "Authentication for step 1. Validating recaptcha response."
                    recaptcha_response = requestParameters.get("g-recaptcha-response")
                    print "Printed recaptcha response: %s" % (recaptcha_response[0])
                    recaptcha_result = self.validateRecaptcha(recaptcha_response[0])
                    if recaptcha_result:
                        logged_in = authenticationService.authenticate(user_name, user_password)
                    else:
                        self.enabled_recaptcha = self.initRecaptcha(configurationAttributes)
                        print "Basic Recaptcha. Authentication for step 1. recaptcha_result: '%s'" % recaptcha_result
                        print "login failed..."
                        print "captcha option: %s" % self.enabled_recaptcha
                        self.prepareForStep(configurationAttributes, requestParameters, step)
                        return False
                        
                else:
                    logged_in = authenticationService.authenticate(user_name, user_password)
            
            if (not logged_in):
                print "login failed for all step"
                self.enabled_recaptcha = self.initRecaptcha(configurationAttributes)
                self.prepareForStep(configurationAttributes, requestParameters, step) 
                return False

            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        identity = CdiUtil.bean(Identity)
        if step == 1: 
            print "Basic. Prepare for Step 1"
            if self.enabled_recaptcha:
                print "Identity parameter has been set..."
                identity.setWorkingParameter("recaptcha_site_key", self.recaptcha_creds['site_key'])
                print "Identity parameter has been set...%s"%self.recaptcha_creds['site_key']
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList(self.recaptcha_creds['site_key'])

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        if step == 1:
            return "/auth/recaptcha/login.xhtml"
        return ""
    
    def initRecaptcha(self, configurationAttributes):
        print "Basic. Initialize recaptcha"
        if not configurationAttributes.containsKey("credentials_file"):
            return False

        cert_creds_file = configurationAttributes.get("credentials_file").getValue2()

        print "Load credentials from file"
        f = open(cert_creds_file, 'r')
        try:
            creds = json.loads(f.read())
        except:
            print "Basic. Initialize recaptcha. Failed to load credentials from file: %s" % cert_creds_file
            return False
        finally:
            f.close()
        
        try:
            recaptcha_creds = creds["recaptcha"]
        except:
            print "Basic. Initialize recaptcha. Invalid credentials file '%s' format:" % cert_creds_file
            return False

        self.recaptcha_creds = None
        if recaptcha_creds["enabled"]:
            print "Basic. Initialize recaptcha. Recaptcha is enabled"
            site_key = recaptcha_creds["site_key"]
            secret_key = recaptcha_creds["secret_key"]
            self.recaptcha_creds = { 'site_key' : site_key, "secret_key" : secret_key }
            print "Basic. Initialize recaptcha. Recaptcha is configured correctly"

            return True
        else:
            print "Basic. Initialize recaptcha. Recaptcha is disabled"

        return False

    def validateRecaptcha(self, recaptcha_response):
        print "Basic. Validate recaptcha response"

        facesContext = CdiUtil.bean(FacesContext)
        request = facesContext.getExternalContext().getRequest()

        remoteip = ServerUtil.getIpAddress(request)
        print "Basic. Validate recaptcha response. remoteip: '%s'" % remoteip

        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 15 * 1000)
        
        recaptcha_validation_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_validation_request = urllib.urlencode({ "secret" : self.recaptcha_creds['secret_key'], "response" : recaptcha_response, "remoteip" : remoteip })
        recaptcha_validation_headers = { "Content-type" : "application/x-www-form-urlencoded", "Accept" : "application/json" }

        try:
            http_service_response = httpService.executePost(http_client, recaptcha_validation_url, None, recaptcha_validation_headers, recaptcha_validation_request)
            http_response = http_service_response.getHttpResponse()
        except:
            print "Basic. Validate recaptcha response. Exception: ", sys.exc_info()[1]
            return False

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "Basic. Validate recaptcha response. Get invalid response from validation server: ", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return False
    
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            httpService.consume(http_response)
        finally:
            http_service_response.closeConnection()

        if response_string == None:
            print "Basic. Validate recaptcha response. Get empty response from validation server"
            return False
        print "printed: %s" % (response_string)
        response = json.loads(response_string)
        print "printed: %s" % (response)
        return response["success"]

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None
    
    def logout(self, configurationAttributes, requestParameters):
        return True
