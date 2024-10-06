# PersonAuthentication External Authn

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import SessionIdService
from org.gluu.oxauth.service import CookieService
from org.gluu.service.cache import CacheProvider
from javax.faces.context import ExternalContext
from java.util import HashMap
from org.gluu.oxauth.service import UserService, RequestParameterService
from org.gluu.oxauth.service.net import HttpService
from javax.faces.context import FacesContext
from org.gluu.jsf2.service import FacesService

import java
import uuid

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript,  configurationAttributes):
        print "PA External Authn. Initialization"
        print "PA External Authn. Initialized successfully configurationAttributes = %s" % configurationAttributes

        self.url_step1 = None

        # Get Custom Properties
        try:
            self.url_step1 = configurationAttributes.get("urlstep1").getValue2()
            print "PA External Authn. Initialization. url_step1: '%s'" % self.url_step1
        except:
            print 'Missing required configuration attribute "urlstep1"'

        return True

    def destroy(self, configurationAttributes):
        print "PA External Authn. Destroy"
        print "PA External Authn. Destroyed successfully"
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
        print "PA External Authn. Authenticate, step: %s, requestParameters: %s" % (step, requestParameters)

        # Retrieve jansKey from request params
        jansKey = ServerUtil.getFirstValue(requestParameters, "jansKey")
        if (jansKey == None):
            print "PA External Authn. Authenticate. Could not find jansKey in request param"
            return False
        print "PA External Authn. Authenticate. jansKey found in request param: '%s'" % jansKey

        # Retrieve jsonValues from cache
        cacheProvider = CdiUtil.bean(CacheProvider)
        jsonValues = cacheProvider.get(jansKey)
        if (jsonValues == None):
            print "PA External Authn. Authenticate. Could not find jsonValues in cache"
            return False
        print "PA External Authn. Authenticate. jsonValues found in cache: %s" % jsonValues

        # Retrieve sessionDn from cacheProvider
        sessionDn = jsonValues.get("sessionDn")
        if (sessionDn == None):
            print "PA External Authn. Authenticate. Could not find sessionDn in cache"
            return False
        print "PA External Authn. Authenticate. sessionDn found in cache: '%s'" % sessionDn

        # Retrieve sessionId by dn
        sessionId = CdiUtil.bean(SessionIdService).getSessionByDn(sessionDn)
        if (sessionId == None):
            print "PA External Authn. Authenticate. Could not find sessionId by dn: '%s'" % sessionDn
            return False
        print "PA External Authn. Authenticate. sessionId found by dn: '%s'" % sessionId.getId()

        # Write sessionId in cookies
        cookieService = CdiUtil.bean(CookieService)
        cookieService.createSessionIdCookie(sessionId, False)
        print "PA External Authn. Authenticate. Writed session in cookies"

        # Set sessionId in Identity
        identity = CdiUtil.bean(Identity)
        identity.setSessionId(sessionId)
        print "PA External Authn. Authenticate. Setted session in identity"

        # Remove jansKey from cache
        cacheProvider.remove(jansKey)
        print "PA External Authn. Authenticate. jansKey removed from cache"

        return True

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        print "PA External Authn. GetPageForStep step: %s" % step

        externalContext = CdiUtil.bean(ExternalContext)
        jansKeyParam = ServerUtil.getFirstValue(externalContext.getRequestParameterValuesMap(), "jansKey")
        if (jansKeyParam == None):
            print "PA External Authn. GetPageForStep could not found jansKey in request param"

            # Remove session id cookie
            cookieService = CdiUtil.bean(CookieService)
            cookieService.removeSessionIdCookie(externalContext.getResponse())
            print "PA External Authn. GetPageForStep remove session id cookie"

            # Retrieve redirectUri from request param and validate it
            redirectUri = ServerUtil.getFirstValue(externalContext.getRequestParameterValuesMap(), "redirect_uri")
            if (redirectUri == None or StringHelper.isEmpty(redirectUri)):
                print "PA External Authn. GetPageForStep redirect_uri is null or empty"
                return ""
            print "PA External Authn. GetPageForStep redirect_uri '%s' found in request param" % redirectUri

            clientId = ServerUtil.getFirstValue(externalContext.getRequestParameterValuesMap(), "client_id")
            if (clientId == None or StringHelper.isEmpty(clientId)):
                print "PA External Authn. GetPageForStep client_id is null or empty"
                return ""
            print "PA External Authn. GetPageForStep client_id '%s' found in request param" % clientId

            # Generate jansKey
            jansKey = str(uuid.uuid4())
            print "PA External Authn. GetPageForStep jansKey '%s' generated" % jansKey

            # Create JSON Values
            jsonValues = {}
            jsonValues["redirectUri"] = str(redirectUri)
            jsonValues["clientId"] = str(clientId)

            cacheProvider = CdiUtil.bean(CacheProvider)
            cacheProvider.put(300, jansKey, jsonValues)
            print "PA External Authn. GetPageForStep jansKey '%s' added to cache: %s" % (jansKey, jsonValues)

            requestParameterService = CdiUtil.bean(RequestParameterService)
            parametersMap = HashMap()
            parametersMap.put("jansKey", jansKey)
            callBackUrl = requestParameterService.parametersAsString(parametersMap)
            callBackUrl = "%s?%s" % (self.url_step1, callBackUrl)

            print "PA External Authn. GetPageForStep redirect to %s" % callBackUrl

            facesService = CdiUtil.bean(FacesService)
            facesService.redirectToExternalURL(callBackUrl)

            return ""

        print "PA External Authn. GetPageForStep jansKey found in request param: %s" % jansKeyParam
        return "postlogin.xhtml"

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True
