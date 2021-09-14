# Author: Madhumita Subramaniam
from java.util import Arrays, Date
from java.io import IOException
from java.lang import Enum
from org.gluu.oxauth.service.net import HttpService
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import AuthenticationService
from org.gluu.oxauth.service.common import UserService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.util import StringHelper, ArrayHelper
from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages
import base64
try:
    import json
except ImportError:
    import simplejson as json
import random

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.identity = CdiUtil.bean(Identity)

    def init(self, customScript, configurationAttributes):
        print("Stytch. Initialization")

        if not configurationAttributes.containsKey("SMS_ENDPOINT"):
            print "Stytch. Initialization. Property SMS_ENDPOINT is mandatory"
            return False
        self.SMS_ENDPOINT = configurationAttributes.get("SMS_ENDPOINT").getValue2()
        
        if not configurationAttributes.containsKey("AUTH_ENDPOINT"):
            print "Stytch. Initialization. Property AUTH_ENDPOINT is mandatory"
            return False
        self.AUTH_ENDPOINT = configurationAttributes.get("AUTH_ENDPOINT").getValue2()
        
        if not configurationAttributes.containsKey("ENROLL_ENDPOINT"):
            print "Stytch. Initialization. Property ENROLL_ENDPOINT is mandatory"
            return False
        self.ENROLL_ENDPOINT = configurationAttributes.get("ENROLL_ENDPOINT").getValue2()
        
        if not configurationAttributes.containsKey("PROJECT_ID"):
            print "Stytch. Initialization. Property PROJECT_ID is mandatory"
            return False
        self.PROJECT_ID = configurationAttributes.get("PROJECT_ID").getValue2()
        
        
        if not configurationAttributes.containsKey("SECRET"):
            print "Stytch. Initialization. Property SECRET is mandatory"
            return False
        self.SECRET = configurationAttributes.get("SECRET").getValue2()       

        print("Stytch Initialized successfully")
        return True

    def destroy(self, configurationAttributes):
        print("Stytch Destroy")
        print("Stytch Destroyed successfully")
        return True

    def getApiVersion(self):
        return 11
        
    def getAuthenticationMethodClaims(self, requestParameters):
        return None
        
    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)

        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()

        session_attributes = self.identity.getSessionId().getSessionAttributes()
        if step == 1:
            print("Stytch Step 1 Password Authentication")
            credentials = self.identity.getCredentials()

            user_name = credentials.getUsername()
            user_password = credentials.getPassword()

            logged_in = False
            if StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password):
                logged_in = authenticationService.authenticate(user_name, user_password)

            if not logged_in:
                return False

            foundUser = None
            try:
                foundUser = authenticationService.getAuthenticatedUser()
            except:
                print("Stytch Error retrieving user {} from LDAP".format(user_name))
                return False

            mobile_number = None
            try:
                isVerified = foundUser.getAttribute("phoneNumberVerified")
                if isVerified:
                    mobile_number = foundUser.getAttribute("employeeNumber")
                if not mobile_number:
                    mobile_number = foundUser.getAttribute("mobile")
                if not mobile_number:
                    mobile_number = foundUser.getAttribute("telephoneNumber")
                if not mobile_number:
                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to determine mobile phone number")
                    print("Stytch Error finding mobile number for user '{}'".format(user_name))
                    return False
            except Exception as e:
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to determine mobile phone number")
                print("Stytch Error finding mobile number for {}: {}".format(user_name, e))
                return False

            self.identity.setWorkingParameter("mobile_number", mobile_number)
            self.identity.getSessionId().getSessionAttributes().put("mobile_number", mobile_number)
            
            mobileDevices = self.getUserAttributeValue(user_name, "oxMobileDevices")
            if mobileDevices is None: 
                # enrollment 
                print "No phones registered. Adding %s " % mobile_number
                phone_id = self.addUser(mobile_number, user_name)
                if phone_id is not None:
                    self.identity.setWorkingParameter("phone_id", phone_id)
                    print "phone_id to which SMS has been sent: %s" % phone_id 
                    return True
                # if enroll is success, send sms and move on to step 2
                else:
                    print "Failed to send sms to user. In the next login attempt, user will be prompted for passcode anyway, so it is safe to return true"
                    return True
                ### end of enrollment
                
            # already contains registered mobiles
            print "mobileDevices: %s" % mobileDevices
            data = json.loads(mobileDevices)
            for phone in data['phones']:
                print "phone number : %s " % phone['number'] 
                print "mobile_number : %s" % mobile_number
                if StringHelper.equals(mobile_number.strip('+'), phone['number'].strip('+')):
                    phone_id = phone['stytch_phone_id']
                    print "phone_id stored in oxMobileDevices: %s " % phone_id
                    if StringHelper.isNotEmptyString(phone_id) :
                        ### authentication
                        self.identity.setWorkingParameter("phone_id", phone_id)
                        phone_id = self.sendPasscodeSMSToUser(mobile_number)
                        print "SendPasscodeSMSToUser: %s " % phone_id
                        if  self.sendPasscodeSMSToUser(mobile_number) is None:
                            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to send message to mobile phone")
                            return False
                        else:
                            print "SMS sent successfully"
                            return True
                        ### end of authentication
                    else: 
                        # enrollment.
                        phone_id = self.addUser(mobile_number, user_name)
                        if phone_id is not None:
                            self.identity.setWorkingParameter("phone_id", phone_id)
                            print "phone_id to which SMS has been sent: %s" % phone_id 
                            return True
                        # if enroll is success, send sms and move on to step 2
                        else:
                            print "Failed to send sms to user. In the next login attempt, user will be prompted for passcode anyway, so it is safe to return true"
                            return True
                        ### end of enrollment
                    
            return False
        elif step == 2:
            form_passcode = ServerUtil.getFirstValue(requestParameters, "passcode")
            print("Stytch form_response_passcode: {}".format(str(form_passcode)))
            phone_id = session_attributes.get("phone_id")
            print("Stytch phone_id: {}".format(str(phone_id)))

            if phone_id is None:
                print("Stytch Failed to find phone_id in session")
                return False

            if form_passcode is None:
                print("Stytch Passcode is empty")
                return False

            if len(form_passcode) != 6:
                print("Stytch Passcode from response is not 6 digits: {}".format(form_passcode))
                return False

            #use the phone_id to send the request for authentication
            result = self.verifyPasscode(phone_id, form_passcode)
            if result is False:
                print("Stytch failed, user entered the wrong code! {} ".format(form_passcode))
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect SMS code, please try again.")
            else: 
                return True

        print("Stytch ERROR: step param not found or != (1|2)")
        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if step == 1:
            print("Stytch Prepare for Step 1")
            return True
        elif step == 2:
            print("Stytch Prepare for Step 2")
            return True

        return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        if step == 2:
            return Arrays.asList("phone_id")
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 2

    def getPageForStep(self, configurationAttributes, step):
        if step == 2:
            return "/auth/otp_sms/otp_sms.xhtml"
        return ""

    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True


    def sendPasscodeSMSToUser(self, phoneNumber):
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()  
        
        data = {"phone_number": phoneNumber    }
        payload = json.dumps(data) 
        encodedString = base64.b64encode((self.PROJECT_ID +":"+self.SECRET).encode('utf-8'))
        headers = {  "Accept" : "application/json"  }
        try:
            http_service_response = httpService.executePost(http_client, self.SMS_ENDPOINT, encodedString, headers, payload)
            http_response = http_service_response.getHttpResponse()
            print "http_response sendPasscodeSMSToUser%s" % http_response
        except:
            print "Stytch. Exception: sendPasscodeSMSToUser", sys.exc_info()[1]
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "Stytch. sendPasscodeSMSToUser: %s" % str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return None
            else :
                response_bytes = httpService.getResponseContent(http_response)
                response_string = httpService.convertEntityToString(response_bytes)
                httpService.consume(http_response)
                response = json.loads(response_string)
                phone_id = response["phone_id"]
                return phone_id
        finally:
            http_service_response.closeConnection()

        return None
    
    def verifyPasscode(self, method_id, code):
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()  
        
        data = {"method_id": method_id, "code": code    }
        payload = json.dumps(data) 
        encodedString = base64.b64encode((self.PROJECT_ID +":"+self.SECRET).encode('utf-8'))
        headers = {  "Accept" : "application/json" }
        try:
            
            http_service_response = httpService.executePost(http_client, self.AUTH_ENDPOINT, encodedString, headers, payload)
            http_response = http_service_response.getHttpResponse()
            print "http_response verifyPasscode - %s" % http_response
        except:
            print "Stytch. Exception: verifyPasscode", sys.exc_info()[1]
            return False

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "Stytch. Verify passcode: ", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return False
            else :
                print "Stytch. User verified"
                return True
        finally:
            http_service_response.closeConnection()

        return False
 
    def hasEnrollments(self, configurationAttributes, user):
        return len(self.getNumbers(user)) > 0
    
    def getNumbers(self, user):
        numbers = set()

        tmp = user.getAttributeValues("mobile")
        if tmp:
            for t in tmp:
                numbers.add(t)

        return list(numbers)
    
    def getUserAttributeValue(self, user_name, attribute_name):
        if StringHelper.isEmpty(user_name):
            return None
        userService = CdiUtil.bean(UserService)
        find_user_by_uid = userService.getUser(user_name, attribute_name)
        if find_user_by_uid == None:
            return None
        custom_attribute_value = userService.getCustomAttribute(find_user_by_uid, attribute_name)
        if custom_attribute_value == None:
            return None
        attribute_value = custom_attribute_value.getValue()
        print "Stytch. Get user attribute. User's %s attribute %s value is %s" % (user_name, attribute_name, attribute_value)
        return attribute_value
    
    def addUser(self, phoneNumber, gluu_user_name):
        httpService = CdiUtil.bean(HttpService)
        http_client = httpService.getHttpsClient()
        userService = CdiUtil.bean(UserService)
        data = {"phone_number": phoneNumber    }
        payload = json.dumps(data) 
        encodedString = base64.b64encode((self.PROJECT_ID +":"+self.SECRET).encode('utf-8'))
        headers = {  "Accept" : "application/json" }
        try:
            http_service_response = httpService.executePost(http_client, self.ENROLL_ENDPOINT, encodedString, headers, payload)
            http_response = http_service_response.getHttpResponse()
            print "http_response %s addUser" % http_response
        except:
            print "Stytch. Exception: addUser ", sys.exc_info()[1]
            return None
        try:
            responseStatusCode = http_response.getStatusLine().getStatusCode();
            print "Stytch. response: %s " % str(http_response.getStatusLine().getStatusCode())
            if responseStatusCode == 200 or responseStatusCode == 201:
                response_bytes = httpService.getResponseContent(http_response)
                response_string = httpService.convertEntityToString(response_bytes)
                httpService.consume(http_response)
                response = json.loads(response_string)
                phone_id = response["phone_id"]
                user_id  = response["user_id"]
                print "phone id %s " % phone_id
                print "user id %s " % user_id
                find_user_by_uid = userService.getUser(gluu_user_name)
                
                oxMobileDevices = json.dumps({'phones': [{'nickname': "Stych Credential", 'number': phoneNumber, 'stytch_phone_id': phone_id, 'stytch_user_id':user_id, 'addedOn': Date().getTime()}]})
                
                userService.setCustomAttribute(find_user_by_uid, "oxMobileDevices", oxMobileDevices)
                updated_user = userService.updateUser(find_user_by_uid)
                if updated_user is not None:
                    return phone_id
                else:
                    print "Stytch. Failed to update user - addUser"
            else:
                print "Stytch. Add user response: ", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return None
                
        finally:
            http_service_response.closeConnection()

        return None