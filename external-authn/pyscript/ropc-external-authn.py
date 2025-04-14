# ResourceOwnerPasswordCredentials External Authn

from org.gluu.model.custom.script.type.owner import ResourceOwnerPasswordCredentialsType
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.oxauth.model.common import SessionIdState
from org.gluu.oxauth.security import Identity
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam
from org.gluu.oxauth.model.config import Constants
from org.gluu.util import StringHelper
from java.lang import String
from java.util import Date, HashMap
from org.gluu.service.cache import CacheProvider

from org.gluu.oxauth.service import RequestParameterService
from org.gluu.oxauth.service.net import HttpService
from javax.faces.context import FacesContext
from org.gluu.jsf2.service import FacesService

class ResourceOwnerPasswordCredentials(ResourceOwnerPasswordCredentialsType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "ROPC External Authn. Initializing ..."
        print "ROPC External Authn. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "ROPC External Authn. Destroying ..."
        print "ROPC External Authn. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 11

    def authenticate(self, context):
        print "ROPC External Authn. Authenticate"

        # Retrieve jansKey from request parameters
        jansKey = context.getHttpRequest().getParameter("jansKey")
        if (jansKey == None or StringHelper.isEmpty(jansKey)):
            print "ROPC External Authn. Authenticate. jansKey not found or empty"
            return False
        print "ROPC External Authn. Authenticate. jansKey '%s' found in request" % jansKey

        cacheProvider = CdiUtil.bean(CacheProvider)
        jsonValues = cacheProvider.get(jansKey)
        if (jsonValues == None):
            print "ROPC External Authn. Authenticate. Could not find jsonValues in cache"
            return False
        print "ROPC External Authn. Authenticate. jsonValues found in cache"

        # Do generic authentication
        authenticationService = CdiUtil.bean(AuthenticationService)

        username = context.getHttpRequest().getParameter("username")
        password = context.getHttpRequest().getParameter("password")
        result = authenticationService.authenticate(username, password)
        if not result:
            print "ROPC External Authn. Authenticate. Could not authenticate user '%s' " % username
            return False

        context.setUser(authenticationService.getAuthenticatedUser())
        print "ROPC External Authn. Authenticate. User '%s' authenticated successfully" % username

        # Get cusom parameters from request
        customParam1Value = context.getHttpRequest().getParameter("custom1")
        customParam2Value = context.getHttpRequest().getParameter("custom2")

        customParameters = {}
        customParameters["custom1"] = customParam1Value
        customParameters["custom2"] = customParam2Value
        print "ROPC External Authn. Authenticate. User '%s'. Creating authenticated session with custom attributes: '%s'" % (username, customParameters)

        session = self.createNewAuthenticatedSession(context, customParameters)

        # This is needed to allow store in token entry sessionId
        authenticationService.configureEventUser(session)
        print "ROPC External Authn. Authenticate. User '%s'. Created authenticated session: '%s'" % (username, customParameters)

        callbackUrl = self.createCallbackUrl(context, jansKey, session, jsonValues)
        if (callbackUrl != None and StringHelper.isNotEmpty(callbackUrl)):
            jsonValues["callbackUrl"] = str(callbackUrl)
            jsonValues["sessionDn"] = session.getDn()
            cacheProvider.put(300, jansKey, jsonValues)
            print "ROPC External Authn. Authenticate. jsonValues stored in cache: '%s'" % jsonValues

        return True

    def createNewAuthenticatedSession(self, context, customParameters={}):
        sessionIdService = CdiUtil.bean(SessionIdService)

        user = context.getUser()
        client = CdiUtil.bean(Identity).getSessionClient().getClient()

        # Add mandatory session parameters
        sessionAttributes = HashMap()
        sessionAttributes.put(Constants.AUTHENTICATED_USER, user.getUserId())
        sessionAttributes.put(AuthorizeRequestParam.CLIENT_ID, client.getClientId())
        sessionAttributes.put(AuthorizeRequestParam.PROMPT, "")

        # Add custom session parameters
        for key, value in customParameters.iteritems():
            if StringHelper.isNotEmpty(value):
                sessionAttributes.put(key, value)

        # Generate authenticated session
        sessionId = sessionIdService.generateAuthenticatedSessionId(context.getHttpRequest(), user.getDn(), sessionAttributes)

        print "ROPC External Authn. Generated sessionId. DN: '%s'" % sessionId.getDn()

        return sessionId

    def createCallbackUrl(self, context, jansKey, sessionId={}, jsonValues={}):
        # Retrieve redirectUri from cache using jansKey
        jsonValRedirectUri = jsonValues.get("redirectUri")
        if (jsonValRedirectUri == None):
            print "ROPC External Authn. CreateCallbackUrl. redirectUri not found in cache"
            return ""
        print "ROPC External Authn. CreateCallbackUrl. redirectUri found '%s' in cache" % jsonValRedirectUri

        # Retrieve clientId from cache using jansKey
        jsonValClientId = jsonValues.get("clientId")
        if (jsonValClientId == None):
            print "ROPC External Authn. CreateCallbackUrl. clientId not found in cache"
            return ""
        print "ROPC External Authn. CreateCallbackUrl. clientId found '%s' in cache" % jsonValClientId

        parameterMap = HashMap()
        parameterMap.put("response_type", "code")
        parameterMap.put("client_id", jsonValClientId)
        parameterMap.put("redirect_uri", jsonValRedirectUri)
        parameterMap.put("jansKey", jansKey)

        requestParameterService = CdiUtil.bean(RequestParameterService)
        parameterString = requestParameterService.parametersAsString(parameterMap)

        authorizeEndpoint = context.getAppConfiguration().getAuthorizationEndpoint()
        jansUrl = "%s?%s" % (authorizeEndpoint, parameterString)

        print "ROPC External Authn. CreateCallbackUrl. jansUrl '%s'" % jansUrl

        return jansUrl