from java.util import Arrays, ArrayList, Optional, Base64

from javax.faces.application import FacesMessage
from javax.faces.context import FacesContext

from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.ping import PPMRequestBroker, UserManagerBroker, ResponseTokenParser, HttpException, TokenProcessingException
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.service import AuthenticationService, UserService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from org.json import JSONObject

try:
    import json
except ImportError:
    import simplejson as json
import sys

class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        

    def init(self, customScript, configurationAttributes):
        print "PingID MFA. init called"
        self.configProperties = configurationAttributes
        
        use_base64_key = self.configProperty("use_base64_key")
        self.token = self.configProperty("token")
        self.org_alias = self.configProperty("org_alias")
        self.authenticator_url = self.configProperty("authenticator_url")
        self.pingAttr = self.configProperty("pingUserAttr")
        self.addNonExistent = False if self.configProperty("addNonExistentPingUser") == None else True
        
        self.userMgmntApiHost = self.configProperty("pingUserAPIHost")
        if self.userMgmntApiHost == None:
            print "PingID MFA. No host for user management API defined. Using a default value"
            self.userMgmntApiHost = "https://idpxnyl3m.pingidentity.com" 
        
        if StringHelper.isEmpty(use_base64_key) or StringHelper.isEmpty(self.token) or StringHelper.isEmpty(self.org_alias) \
            or StringHelper.isEmpty(self.authenticator_url) or StringHelper.isEmpty(self.pingAttr):
            print "PingID MFA. One or more required Script properties are missing. Check the docs"
            return False
        
        self.secret = Base64.getDecoder().decode(use_base64_key)
        
        print "PingID MFA. Initialized successfully"
        return True


    def destroy(self, configurationAttributes):
        print "PingID MFA. Destroyed called"
        return True


    def getApiVersion(self):
        return 11


    def getAuthenticationMethodClaims(self, configurationAttributes):
        return None


    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "PingID MFA. isValidAuthenticationMethod called"
        return True


    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None


    def authenticate(self, configurationAttributes, requestParameters, step):
        print "PingID MFA. authenticate for step %s" % str(step)
        
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        
        try:
            if step == 1:
                credentials = identity.getCredentials()
                user_name = credentials.getUsername()
                user_password = credentials.getPassword()
    
                if StringHelper.isEmptyString(user_name) or StringHelper.isEmptyString(user_password) or \
                    not authenticationService.authenticate(user_name, user_password):
                    return False

                print "PingID MFA. User '%s' has authenticated successfully" % user_name
                remote = self.remoteUserId(authenticationService.getAuthenticatedUser())
                
                if remote == None:
                    # Accept the local-only user
                    identity.setWorkingParameter("singleStep", "yes")
                    return True
                else:
                    print "PingID MFA. Local user '%s' mapped to remote '%s'" % (user_name, remote)
                
                client = UserManagerBroker(remote, self.org_alias, self.token, self.secret, self.userMgmntApiHost)
                print "PingID MFA. Calling getUserDetails API endpoint"
                userJson = client.getUserDetails()

                # If user does not exist at ping side, create it if required
                if userJson.isNull("userDetails"):
                    if self.addNonExistent:
                        userJson = client.addUser()
                    else:
                        # Fail
                        self.setError("%s is not a PingID user" % remote)
                        return False
                
                userJson = userJson.getJSONObject("userDetails")
                ndevices = self.devicesCount(userJson)
                print "PingID MFA. User has %d devices registered" % ndevices
                
                if ndevices == 0:                    
                    code = self.activationCode(client, userJson.optString("status"))
                    if code == None:
                        print "PingID MFA. Unable to get an activation code for pingID user '%s'" % remote
                        self.setError("We couldn't obtain an activation code for you!")
                    else:
                        givenName = userJson.optString("fname", None)
                        if givenName != None:
                            identity.setWorkingParameter("givenName", givenName)
                            
                        identity.setWorkingParameter("qrCodeRequest", client.getQRCodeLink(str(code)))
                        
                        timeout = CdiUtil.bean(AppConfiguration).getSessionIdUnauthenticatedUnusedLifetime()
                        identity.setWorkingParameter("timeout", timeout - 10)
                        
                        return True
                else:
                    self.preparePPMRequest(remote)
                    return True
                    
            elif step == 2:
                
                if identity.getWorkingParameter("qrCodeRequest") == None:
                    # Flow will have only 2 steps in total
                    return self.processPPMResponse(requestParameters)
                    
                else:                    
                    foundUser = authenticationService.getAuthenticatedUser()
                    if foundUser == None:
                        # session may have expired
                        print "PingID MFA. No authenticated user found"
                        # Avoid generating QRs endlessly from the UI
                        identity.setWorkingParameter("qrCodeRequest", None)
                        
                        return False
                    
                    # This should evaluate non null
                    remote = self.remoteUserId(foundUser)
    
                    client = UserManagerBroker(remote, self.org_alias, self.token, self.secret, self.userMgmntApiHost)
                    print "PingID MFA. Calling getUserDetails API endpoint"
                    userJson = client.getUserDetails().getJSONObject("userDetails")
                    
                    ndevices = self.devicesCount(userJson) 
                                              
                    if ndevices == 0:
                        # There should be devices (user is supposed to have enrolled already earlier), 
                        # but he could have simply pressed the continue button without scanning the QR
                        
                        print "PingID MFA. Unexpectedly user has no enrolled devices"
                        # Avoid generating QRs endlessly from the UI
                        identity.setWorkingParameter("qrCodeRequest", None)
                    else:
                        self.preparePPMRequest(remote)
                        return True
                    
            elif step == 3:                
                return self.processPPMResponse(requestParameters)
                
        except TokenProcessingException:
            print "PingID MFA. Error in token processing:", sys.exc_info()[1]
        except HttpException as e:
            if e.getStatusCode() != None:
                print "PingID MFA. HTTP status %d" % e.getStatusCode()
            if e.getResponse() != None:
                print "PingID MFA. HTTP response:", e.getResponse()
            print "PingID MFA. HTTP Error:", sys.exc_info()[1]
        
        # Assume failure by default
        return False
        
        
    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "PingID MFA. prepareForStep %d" % step
        return True
        
        
    def getExtraParametersForStep(self, configurationAttributes, step):
        print "PingID MFA. getExtraParametersForStep %d" % step
        list = ArrayList()
        if step > 1:
            list.addAll(Arrays.asList("givenName", "qrCodeRequest", "timeout"))
            list.addAll(Arrays.asList("ppmNonce", "ppmRequest", "issuer", "idpAccountId", "authenticatorUrl"))
        return list


    def getCountAuthenticationSteps(self, configurationAttributes):
        print "PingID MFA. getCountAuthenticationSteps called"
        identity = CdiUtil.bean(Identity)
        if identity.getWorkingParameter("singleStep") != None:
            return 1
        else:
            return 2 if identity.getWorkingParameter("qrCodeRequest") == None else 3
        
        
    def getPageForStep(self, configurationAttributes, step):
        print "PingID MFA. getPageForStep called %d" % step
        
        if step == 1:
            return "/auth/pingid/login.xhtml"
            
        elif CdiUtil.bean(Identity).getWorkingParameter("qrCodeRequest") == None:
            print "===="
            return "/auth/pingid/ppm.xhtml"
            
        elif step == 2:
            return "/auth/pingid/enroll.xhtml"
        
        else:
            return "/auth/pingid/ppm.xhtml"
        
        
    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "PingID MFA. getNextStep called %d" % step
        return -1
        

    def logout(self, configurationAttributes, requestParameters):
        print "PingID MFA. logout called"
        return True
      
# MISC ROUTINES

    def configProperty(self, name):
        prop = self.configProperties.get(name)
        return None if prop == None else prop.getValue2()
        
    def remoteUserId(self, localUser):
        # See class org.gluu.persist.model.base.SimpleUser
        return localUser.getUserId() if self.pingAttr == "uid" else localUser.getAttribute(self.pingAttr) 
        
    def devicesCount(self, userJson):
        devices = userJson.optJSONArray("devicesDetails")
        return 0 if devices == None else devices.length()
        
        
    def activationCode(self, client, status):
        
        code = 0
        print "PingID MFA. User status is '%s'" % status
        if status != "SUSPENDED":
            
            if status != "ACTIVE" and status != 'PENDING_CHANGE_DEVICE':
                code = client.activateUser().optLong("activationCode")
            
            if code == 0:
                code = client.getActivationCode().optLong("activationCode")
                
        return None if code == 0 else code


    def preparePPMRequest(self, username):
        
        print "PingID MFA. Preparing a PPM request for web authenticator"
        serverName = CdiUtil.bean(FacesContext).getExternalContext().getRequest().getServerName()
        returnUrl = "https://%s/oxauth/postlogin.htm" % serverName
            
        issuer = "gluu"
        req = PPMRequestBroker(self.org_alias, self.token, issuer, returnUrl, self.org_alias, self.secret, 120)
        req.populate(username)
        
        identity = CdiUtil.bean(Identity)
        identity.setWorkingParameter("ppmNonce", req.getNonce())
        identity.setWorkingParameter("ppmRequest", req.getSignedRequest())
        identity.setWorkingParameter("issuer", issuer)
        identity.setWorkingParameter("idpAccountId", self.org_alias)
        identity.setWorkingParameter("authenticatorUrl", self.authenticator_url + "/auth")
        
        
    def processPPMResponse(self, requestParameters):
        
        # Process upcoming data from pingID authenticator web app
        encodedRes = ServerUtil.getFirstValue(requestParameters, "ppm_response")
        
        if StringHelper.isEmpty(encodedRes):
            print "PingID MFA. PPM response is empty!"
            return False
        
        parser = ResponseTokenParser(self.org_alias, self.token, self.secret)
        json = parser.parse(encodedRes)
        success = json.optString("status") == "success"
        nonce = json.optString("nonce", None)
        
        # Sometimes nonce is absent in the PPM response
        if success or nonce != None:
            if nonce != CdiUtil.bean(Identity).getWorkingParameter("ppmNonce"):
                print "PingID MFA. Nonce response validation failed"
                return False
            
        if success:
            print "PingID MFA. PPM authentication succeeded"
            return True
            
        else:
            error = json.optString("message")
            print "PingID MFA. PPM authentication failed with code %s" % json.optString("errorCode")
            print "PingID MFA. %s" % error
            self.setError(error)
            
        return False
        
        
    def setError(self, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(FacesMessage.SEVERITY_ERROR, msg)
        