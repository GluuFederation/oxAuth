# Author: Jose Gonzalez
# Author: Madhumita Subramaniam

from java.lang import System
from java.net import URLDecoder, URLEncoder
from java.util import Arrays, ArrayList, Collections, HashMap
from org.gluu.oxauth.service import  ClientService
from org.gluu.service.net import NetworkService
from org.gluu.oxauth.service.net import HttpService
from javax.faces.application import FacesMessage
from javax.servlet.http import Cookie
from javax.faces.context import FacesContext
from org.oxauth.persistence.model.configuration import GluuConfiguration
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.service import CacheService
from org.gluu.oxauth.service import AuthenticationService, UserService
from org.gluu.oxauth.service.custom import CustomScriptService
from org.gluu.model.custom.script import CustomScriptType
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.model import SimpleCustomProperty
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from java.time import LocalDateTime, Duration
from org.gluu.jsf2.message import FacesMessages

try:
    import json
except ImportError:
    import simplejson as json
import sys

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.ACR_SG = "super_gluu"
        self.PREV_LOGIN_SETTING = "prevLoginsCookieSettings"
        self.modulePrefix = "pwdless-external_"
        # expiration time in seconds - adds up to 1 year
        self.lockExpirationTime = 31536000 
        

    def init(self, customScript, configurationAttributes):    	
        print "Deduce Passwordless. init called"
        if not configurationAttributes.containsKey("DEDUCE_ENDPOINT"):
            print "Deduce Passwordless. Initialization. Property DEDUCE_ENDPOINT is mandatory"
            return False
        self.DEDUCE_ENDPOINT = configurationAttributes.get("DEDUCE_ENDPOINT").getValue2()
        
        if not configurationAttributes.containsKey("DEDUCE_SITE"):
            print "Deduce Passwordless. Initialization. Property DEDUCE_SITE is mandatory"
            return False
        self.DEDUCE_SITE = configurationAttributes.get("DEDUCE_SITE").getValue2()
        
        
        if not configurationAttributes.containsKey("DEDUCE_API_KEY"):
            print "Deduce Passwordless. Initialization. Property DEDUCE_API_KEY is mandatory"
            return False
        self.DEDUCE_API_KEY = configurationAttributes.get("DEDUCE_API_KEY").getValue2()
        
        self.authenticators = {}
        self.uid_attr = self.getLocalPrimaryKey()
        
        self.prevLoginsSettings = self.computePrevLoginsSettings(configurationAttributes.get(self.PREV_LOGIN_SETTING))

        custScriptService = CdiUtil.bean(CustomScriptService)
        self.scriptsList = custScriptService.findCustomScripts(Collections.singletonList(CustomScriptType.PERSON_AUTHENTICATION), "oxConfigurationProperty", "displayName", "oxEnabled")
        dynamicMethods = self.computeMethods(configurationAttributes.get("snd_step_methods"), self.scriptsList)

        if len(dynamicMethods) > 0:
            print "Deduce Passwordless. init. Loading scripts for dynamic modules: %s" % dynamicMethods
            
            for acr in dynamicMethods:
                moduleName = self.modulePrefix + acr
                try:
                    external = __import__(moduleName, globals(), locals(), ["PersonAuthentication"], -1)
                    module = external.PersonAuthentication(self.currentTimeMillis)

                    print "Deduce Passwordless. init. Got dynamic module for acr %s" % acr
                    configAttrs = self.getConfigurationAttributes(acr, self.scriptsList)
                    
                    if acr == self.ACR_SG:
                        application_id = configurationAttributes.get("supergluu_app_id").getValue2()
                        configAttrs.put("application_id", SimpleCustomProperty("application_id", application_id))

                    if module.init(None, configAttrs):
                        module.configAttrs = configAttrs
                        self.authenticators[acr] = module
                    else:
                        print "Deduce Passwordless. init. Call to init in module '%s' returned False" % moduleName
                except:
                    print "Deduce Passwordless. init. Failed to load module %s" % moduleName
                    print "Exception: ", sys.exc_info()[1]
        else:
            print "Deduce Passwordless. init. Not enough custom scripts enabled. Check config property 'snd_step_methods'"
            return False
        
        print "Deduce Passwordless. init. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, configurationAttributes):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "Deduce Passwordless. authenticate for step %d" % step

        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)

        if step == 1:
            user_name = identity.getCredentials().getUsername()
            if StringHelper.isNotEmptyString(user_name):

                foundUser = userService.getUserByAttribute(self.uid_attr, user_name)
                
                if foundUser == None:
                    print "Deduce Passwordless. Unknown username '%s'" % user_name
                elif authenticationService.authenticate(user_name):
                    availMethods = self.getAvailMethodsUser(foundUser)
                    
                    # deduce - impossible travel feature
                    identity = CdiUtil.bean(Identity)
                    #session_attributes = identity.getSessionId().getSessionAttributes()
                    ip = str( ServerUtil.getFirstValue(requestParameters, "loginForm:clientIP")).encode('utf-8') 
                    email = str(foundUser.getAttribute("mail")).encode('utf-8')
                    print "platform %s" %str( ServerUtil.getFirstValue(requestParameters,  "loginForm:platform"))
                    platform = json.loads(str( ServerUtil.getFirstValue(requestParameters,  "loginForm:platform")).encode('utf-8'))
                    action = "auth.success"
                    impossibleTravel = self.sendInsightsRequest(ip, email, platform["name"], action)
                    if (impossibleTravel is True):
                        self.lockUser(user_name)
                    else:
                        if availMethods.size() > 0:
                            acr = availMethods.get(0)
                            print "Deduce Passwordless. Method to try in 2nd step will be: %s" % acr
                            
                            module = self.authenticators[acr]
                            logged_in = module.authenticate(module.configAttrs, requestParameters, step)
                            
                            if logged_in:
                                identity.setWorkingParameter("ACR", acr)
                                print "Deduce Passwordless. Authentication passed for step %d" % step
                                return True
                            
                        else:
                            self.setError("Cannot proceed. You don't have suitable credentials for passwordless login")
                else:
                    self.setError("Wrong username or password")
        else:
            print "authenticate step 2"
            user = authenticationService.getAuthenticatedUser()
            if user == None:
                print "Deduce Passwordless. authenticate for step 2. Cannot retrieve logged user"
                return False

            #see alternative.xhtml
            identity = CdiUtil.bean(Identity)
            session_attributes = identity.getSessionId().getSessionAttributes()
            alter = session_attributes.get("alternativeMethod")
            if alter != None:
                #bypass the rest of this step if an alternative method was provided. Current step will be retried (see getNextStep)
                self.simulateFirstStep(requestParameters, alter)
                return True

            session_attributes = identity.getSessionId().getSessionAttributes()
            acr = session_attributes.get("ACR")
            #this working parameter is used in alternative.xhtml
            identity.setWorkingParameter("methods", self.getAvailMethodsUser(user, acr))

            success = False
            if acr in self.authenticators:
                module = self.authenticators[acr]
                success = module.authenticate(module.configAttrs, requestParameters, step)

            if success:
                print "Deduce Passwordless. authenticate. 2FA authentication was successful"
                if self.prevLoginsSettings != None:
                    self.persistCookie(user)
            else:
                print "Deduce Passwordless. authenticate. 2FA authentication failed"

            return success
            
        return False
        

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "Deduce Passwordless. prepareForStep %d" % step

        identity = CdiUtil.bean(Identity)
        session_attributes = identity.getSessionId().getSessionAttributes()
        
        if step == 1:
            try:
                loginHint = session_attributes.get("login_hint")
                print "Deduce Passwordless. prepareForStep. Login hint is %s" % loginHint
                isLoginHint = loginHint != None
                
                if self.prevLoginsSettings == None:
                    if isLoginHint:
                        identity.setWorkingParameter("loginHint", loginHint)
                else:
                    users = self.getCookieValue()    
                    
                    if isLoginHint:
                        
                        idx = self.findUid(loginHint, users) 
                        if idx >= 0:
                            u = users.pop(idx)
                            users.insert(0, u)
                        else:
                            identity.setWorkingParameter("loginHint", loginHint)
                    
                    if len(users) > 0:
                        identity.setWorkingParameter("users", json.dumps(users, separators=(',',':')))
            
                # In login.xhtml both loginHint and users are used to properly display the login form
            except:
                print "Deduce Passwordless. prepareForStep. Error!", sys.exc_info()[1]
                
            return True
            
        else:
            user = CdiUtil.bean(AuthenticationService).getAuthenticatedUser()

            if user == None:
                print "Deduce Passwordless. prepareForStep. Cannot retrieve logged user"
                return False
                
            acr = session_attributes.get("ACR")
            print "Deduce Passwordless. prepareForStep. ACR = %s" % acr
            
            identity.setWorkingParameter("methods", ArrayList(self.getAvailMethodsUser(user, acr)))

            if acr in self.authenticators:
                module = self.authenticators[acr]
                return module.prepareForStep(module.configAttrs, requestParameters, step)
            else:
                return False

    def getExtraParametersForStep(self, configurationAttributes, step):

        print "Deduce Passwordless. getExtraParametersForStep %d" % step
        list = ArrayList()
        if step > 1:
            acr = CdiUtil.bean(Identity).getWorkingParameter("ACR")

            if acr in self.authenticators:
                module = self.authenticators[acr]
                params = module.getExtraParametersForStep(module.configAttrs, step)
                if params != None:
                    list.addAll(params)

            list.addAll(Arrays.asList("ACR", "methods"))
            print "extras are %s" % list
        return list

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 2

    def getPageForStep(self, configurationAttributes, step):
        if step > 1:
            identity = CdiUtil.bean(Identity)
            acr = CdiUtil.bean(Identity).getWorkingParameter("ACR")
            if acr in self.authenticators:
                module = self.authenticators[acr]
                page = module.getPageForStep(module.configAttrs, step)
                
                print "Deduce Passwordless. getPageForStep %d is %s" % (step, page)                
                return page
                
        return "/auth/deduce/loginD.xhtml"

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "Deduce Passwordless. getNextStep called %d" % step
        identity = CdiUtil.bean(Identity)
        if step > 1:
            session_attributes = identity.getSessionId().getSessionAttributes()
            acr = session_attributes.get("alternativeMethod")
            if acr != None:
                print "Deduce Passwordless. getNextStep. Use alternative method %s" % acr
                CdiUtil.bean(Identity).setWorkingParameter("ACR", acr)
                #retry step with different acr
                return 2
        return -1

    def logout(self, configurationAttributes, requestParameters):
        return True

# Miscelaneous

    def getLocalPrimaryKey(self):
        entryManager = CdiUtil.bean(PersistenceEntryManager)
        config = GluuConfiguration()
        config = entryManager.find(config.getClass(), "ou=configuration,o=gluu")
        #Pick (one) attribute where user id is stored (e.g. uid/mail)
        uid_attr = config.getOxIDPAuthentication().get(0).getConfig().getPrimaryKey()
        print "Deduce Passwordless. init. uid attribute is '%s'" % uid_attr
        return uid_attr


    def setError(self, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(FacesMessage.SEVERITY_ERROR, msg)


    def computeMethods(self, sndStepMethods, scriptsList):
        snd_step_methods = [] if sndStepMethods == None else StringHelper.split(sndStepMethods.getValue2(), ",")        
        methods = []
        
        for m in snd_step_methods:
            for customScript in scriptsList:
                if customScript.getName() == m and customScript.isEnabled():
                    methods.append(m)

        print "Deduce Passwordless. computeMethods. %s" % methods
        return methods


    def getConfigurationAttributes(self, acr, scriptsList):

        configMap = HashMap()
        for customScript in scriptsList:
            if customScript.getName() == acr:
                for prop in customScript.getConfigurationProperties():
                    configMap.put(prop.getValue1(), SimpleCustomProperty(prop.getValue1(), prop.getValue2()))

        print "Deduce Passwordless. getConfigurationAttributes. %d configuration properties were found for %s" % (configMap.size(), acr)
        return configMap


    def getAvailMethodsUser(self, user, skip=None):
        methods = ArrayList()

        for method in self.authenticators:
            try:
                module = self.authenticators[method]
                if module.hasEnrollments(module.configAttrs, user) and (skip == None or skip != method):
                    methods.add(method)
            except:
                print "Deduce Passwordless. getAvailMethodsUser. hasEnrollments call could not be issued for %s module" % method
                print "Exception: ", sys.exc_info()[1]

        print "Deduce Passwordless. getAvailMethodsUser %s" % methods.toString()
        return methods


    def simulateFirstStep(self, requestParameters, acr):
        #To simulate 1st step, there is no need to call:
        # getPageforstep (no need as user/pwd won't be shown again)
        # isValidAuthenticationMethod (by restriction, it returns True)
        # prepareForStep (by restriction, it returns True)
        # getExtraParametersForStep (by restriction, it returns None)
        print "Deduce Passwordless. simulateFirstStep. Calling authenticate (step 1) for %s module" % acr
        if acr in self.authenticators:
            module = self.authenticators[acr]
            auth = module.authenticate(module.configAttrs, requestParameters, 1)
            print "Deduce Passwordless. simulateFirstStep. returned value was %s" % auth
            
    def computePrevLoginsSettings(self, customProperty):
        settings = None
        if customProperty == None:
            print "Deduce Passwordless. Previous logins feature is not configured. Set config property '%s' if desired" % self.PREV_LOGIN_SETTING
        else:
            try:
                settings = json.loads(customProperty.getValue2())
                if settings['enabled']:
                	print "Deduce Passwordless. PrevLoginsSettings are %s" % settings
                else:
                    settings = None
                    print "Deduce Passwordless. Previous logins feature is disabled"
            except:
                print "Deduce Passwordless. Unparsable config property '%s'" % self.PREV_LOGIN_SETTING
            
        return settings
        
    def getCookieValue(self):
        ulist = []
        coo =  None
        httpRequest = ServerUtil.getRequestOrNull()
        
        if httpRequest != None:
            for cookie in httpRequest.getCookies():
                if cookie.getName() == self.prevLoginsSettings['cookieName']:
                   coo = cookie
        
        if coo == None:
            print "Deduce Passwordless. getCookie. No cookie found"
        else:
            print "Deduce Passwordless. getCookie. Found cookie"
            forgetMs = self.prevLoginsSettings['forgetEntriesAfterMinutes'] * 60 * 1000
            
            try:
                now = System.currentTimeMillis()
                value = URLDecoder.decode(coo.getValue(), "utf-8")
                # value is an array of objects with properties: uid, displayName, lastLogon
                value = json.loads(value)
                
                for v in value:
                    if now - v['lastLogon'] < forgetMs:
                        ulist.append(v)        
                # print "==========", ulist
            except:
                print "Deduce Passwordless. getCookie. Unparsable value, dropping cookie..."
            
        return ulist
        

    def findUid(self, uid, users):
        
        i = 0
        idx = -1
        for user in users:
            if user['uid'] == uid:
                idx = i
                break
            i+=1
        return idx
        
            
    def persistCookie(self, user):
        try:
            now = System.currentTimeMillis()
            uid = user.getUserId()
            dname = user.getAttribute("displayName")
            
            users = self.getCookieValue()
            idx = self.findUid(uid, users)
            
            if idx >= 0:
                u = users.pop(idx)
            else:
                u = { 'uid': uid, 'displayName': '' if dname == None else dname }
            u['lastLogon'] = now
            
            # The most recent goes first :)
            users.insert(0, u)
            
            excess = len(users) - self.prevLoginsSettings['maxListSize']            
            if excess > 0:
                print "Deduce Passwordless. persistCookie. Shortening list..."
                users = users[:self.prevLoginsSettings['maxListSize']]
            
            value = json.dumps(users, separators=(',',':'))
            value = URLEncoder.encode(value, "utf-8")
            coo = Cookie(self.prevLoginsSettings['cookieName'], value)
            coo.setSecure(True)
            coo.setHttpOnly(True)
            # One week
            coo.setMaxAge(7 * 24 * 60 * 60)
            
            response = self.getHttpResponse()
            if response != None:
                print "Deduce Passwordless. persistCookie. Adding cookie to response"
                response.addCookie(coo)
        except:
            print "Deduce Passwordless. persistCookie. Exception: ", sys.exc_info()[1]


    def getHttpResponse(self):
        try:
            return FacesContext.getCurrentInstance().getExternalContext().getResponse()
        except:
            print "Deduce Passwordless. Error accessing HTTP response object: ", sys.exc_info()[1]
            return None
   
    def getSessionAttribute(self, attribute_name):
        identity = CdiUtil.bean(Identity)
        # Try to get attribute value from Seam event context
        if identity.isSetWorkingParameter(attribute_name):
            return identity.getWorkingParameter(attribute_name)
        # Try to get attribute from persistent session
        session_id = identity.getSessionId()
        if session_id == None:
            return None
        session_attributes = session_id.getSessionAttributes()
        if session_attributes == None:
            return None
        if session_attributes.containsKey(attribute_name):
            return session_attributes.get(attribute_name)
        return None   
    
    def sendInsightsRequest(self, ip, email, platform, action):
        httpService = CdiUtil.bean(HttpService)
        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()  
        
        data = { "site":self.DEDUCE_SITE,"apikey":self.DEDUCE_API_KEY,"ip":ip, "email":email,"user_agent":platform, "action": action }
        payload = json.dumps(data) 
        headers = {  "Accept" : "application/json" }
        print "Deduce Passwordless. payload %s " % payload
        try:
            http_service_response = httpService.executePost(http_client, self.DEDUCE_ENDPOINT, None, headers, payload)
            http_response = http_service_response.getHttpResponse()
            print "http_response %s" % http_response
        except:
            print "Deduce Passwordless. Exception: ", sys.exc_info()[1]
            return False

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "Deduce Passwordless. Got invalid response from validation server: ", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return False
    
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            print "response_string %s" %response_string
            httpService.consume(http_response)
            if ("IMPOSSIBLE_TRAVEL" in response_string):
                return True
        finally:
            http_service_response.closeConnection()

        if response_string is None:
            print "Deduce Passwordless. Got empty response from validation server"
            return False
        
        return False  
    
    def lockUser(self, user_name):
        if StringHelper.isEmpty(user_name):
            return None

        userService = CdiUtil.bean(UserService)
        cacheService= CdiUtil.bean(CacheService)
       
        find_user_by_uid = userService.getUser(user_name)
        if (find_user_by_uid == None):
            return None

        status_attribute_value = userService.getCustomAttribute(find_user_by_uid, "gluuStatus")
        if status_attribute_value != None:
            user_status = status_attribute_value.getValue()
            if StringHelper.equals(user_status, "inactive"):
                print "Deduce Passwordless. (lock account). Lock user. User '%s' locked already" % user_name
                return 
        
        userService.setCustomAttribute(find_user_by_uid, "gluuStatus", "inactive")
        updated_user = userService.updateUser(find_user_by_uid)

        object_to_store = json.dumps({'locked': True, 'created': LocalDateTime.now().toString()}, separators=(',',':'))

        cacheService.put(StringHelper.toString(self.lockExpirationTime), "lock_user_"+user_name, object_to_store);
        self.setError( "Impossible travel detected. Your account has been locked. Please contact the administrator")

        print "Deduce Passwordless. (lock account). Lock user. User '%s' locked" % user_name