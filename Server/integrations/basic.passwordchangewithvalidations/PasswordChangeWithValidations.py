# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
# Author: Hemant Mehta
#

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import UserService, AuthenticationService
from org.gluu.service import CacheService
from org.gluu.util import StringHelper, ArrayHelper
from org.gluu.oxauth.util import ServerUtil

from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages

from zxcvbn import zxcvbn

import java

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Basic (with password update). Initialization"
        print "Basic (with password update). Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "Basic (with password update). Destroy"
        print "Basic (with password update). Destroyed successfully"
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

        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()

        if (step == 1):
            print "Basic (with password update). Authenticate for step 1"
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            user_password = credentials.getPassword()

            logged_in = False
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isEmptyString(user_password)):
                facesMessages.add(FacesMessage.SEVERITY_INFO, "Password is empty! Enter your password")
                print "Basic. Authenticate: Password is empty! Enter your password"
                return False

            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                find_user = userService.getUser(user_name)
                if (find_user == None):
                    facesMessages.add(FacesMessage.SEVERITY_INFO, "User doesn't Exist")
                    return False
                else:
                    print "Basic . Authenticate for step 1-4-disablechecking"
                    user_status = userService.getCustomAttribute(find_user, "gluuStatus")
                    print "Basic . Authenticate for step 1-5-disablechecking"
                    if (user_status != None):
                        user_status_value = user_status.getValue()
                        if (StringHelper.equals(user_status_value, "inactive")): 
                            facesMessages.add(FacesMessage.SEVERITY_INFO, "User is Disabled")                            
                            return False 	
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                logged_in = authenticationService.authenticate(user_name, user_password)

            if (not logged_in):
                return False

            return True
        elif (step == 2):
            print "Basic (with password update). Authenticate for step 2-see"
            user = authenticationService.getAuthenticatedUser()
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            if user == None:
                print "Basic (with password update). Authenticate for step 2. Failed to determine user name"
                return False

            user_name = user.getUserId()
            find_user_by_uid = userService.getUser(user_name)

            update_button = requestParameters.get("loginForm:updateButton")

            if ArrayHelper.isEmpty(update_button):
                return True

            new_password_array = requestParameters.get("loginForm:password")
            new_password = new_password_array[0]  
            if ArrayHelper.isEmpty(new_password_array) or StringHelper.isEmpty(new_password):
                print "Basic (with password update). Authenticate for step 2. New password is empty"
                return False
			
          
            print "Basic (with password update). Authenticate for step 2. see the new password ================'%s'" % new_password

            results = zxcvbn(new_password)
            if results['score'] <2:
                print 'Its a weak Password, please increase the complexity.'
                facesMessages.add(FacesMessage.SEVERITY_INFO, "Its weak password, please increase the complexity.")
                return False

            find_user_by_uid.setAttribute("userPassword", new_password)


            print "Basic (with password update). Authenticate for step 2. Attempting to set new user '%s' password " % user_name


            userService.updateUser(find_user_by_uid)
            print "Basic (with password update). Authenticate for step 2. Password updated successfully"

            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic (with password update). Prepare for Step 1"
            return True
        elif (step == 2):
            print "Basic (with password update). Prepare for Step 2-confirm"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 2

    def getPageForStep(self, configurationAttributes, step):
        if (step == 2):
            print "Basic (with password update). Redirecting to password change page"
            return "/auth/pwd/newpassword.xhtml"

        return ""
        
    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None
        
    def logout(self, configurationAttributes, requestParameters):
        return True
