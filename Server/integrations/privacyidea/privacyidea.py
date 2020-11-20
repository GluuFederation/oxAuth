# -*- coding: utf-8 -*-
#
# privacyIDEA is a Multi-Factor-Management system that supports
# a wide variety of different tokentypes like smartphone apps, key fob tokens,
# yubikeys, u2f, fido2, email, sms...
# The administrator of an organization can manage the 2nd factors of the
# users centrally in privacyIDEA and connect any application with privacyIDEA
# to secure the login process.
#
# This authentication script adds a most flexible multi-factor-authentication
# to Gluu. See:
#      https://privacyidea.org
# Get enterprise support at:
#      https://netknights.it/en/produkte/privacyidea/
#
# License:  AGPLv3
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
__doc__ = """This script enables Gluu to communicate to privacyIDEA server
and have the privacyIDEA verify the second factor.
"""

__version__ = "1.0.0"

from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import UserService
from org.gluu.util import StringHelper

from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages

from java.util import Arrays
import sys

PI_USER_AGENT = "privacyIDEA-Gluu"
GLUU_API_VERSION = 11


def logFromSDK(message):
    print("privacyIDEA. JavaSDK: " + message)

class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, currentTimeMillis):
        print("__init__")
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print("privacyIDEA. init")
        self.pi = None

        sdk_path = "/opt/java_sdk.jar"
        if configurationAttributes.containsKey("sdk_path"):
            sdk_path = configurationAttributes.get("sdk_path").getValue2()

        sys.path.append(sdk_path)
        try:
            from org.privacyidea import Challenge
            from org.privacyidea import PrivacyIDEA
            from org.privacyidea import PIResponse
        except ImportError:
            print("privacyIDEA. Java SDK import not found! Make sure the jar is located at '{}'.".format(sdk_path))
            # returning success here allows to display a error message in the authenticate function
            # because self.pi will be None
            return True

        if not configurationAttributes.containsKey("privacyidea_url"):
            print("privacyIDEA. Missing mandatory configuration value 'privacyidea_url'!")
            return True

        privacyidea_url = configurationAttributes.get("privacyidea_url").getValue2()

        builder = PrivacyIDEA.Builder(privacyidea_url, PI_USER_AGENT)

        if configurationAttributes.containsKey("log_from_sdk"):
            builder.setSimpleLog(logFromSDK)

        if configurationAttributes.containsKey("sslverify"):
            sslverify = configurationAttributes.get("sslverify").getValue2()
            builder.setSSLVerify(sslverify != "0")

        if configurationAttributes.containsKey("realm"):
            realm = configurationAttributes.get("realm").getValue2()
            builder.setRealm(realm)
        else:
            print("privacyIDEA. Config param 'realm' not set")

        self.disableGluuPass = False
        if configurationAttributes.containsKey("disablegluupass"):
            self.disableGluuPass = configurationAttributes.get("disablegluupass").getValue2() == "1"

        # Load configuration for optional trigger challenge or send password in first step
        self.sendPassword = False
        self.triggerChallenge = False
        serviceAccountName = None
        serviceAccountPass = None
        serviceAccountRealm = None

        if configurationAttributes.containsKey("triggerchallenges"):
            self.triggerChallenge = configurationAttributes.get("triggerchallenges").getValue2() == "1"

        if configurationAttributes.containsKey("sendpassword"):
            self.sendPassword = configurationAttributes.get("sendpassword").getValue2() == "1"

        if configurationAttributes.containsKey("serviceaccountname"):
            serviceAccountName = configurationAttributes.get("serviceaccountname").getValue2()
            
        if configurationAttributes.containsKey("serviceaccountpass"):
            serviceAccountPass = configurationAttributes.get("serviceaccountpass").getValue2()

        if serviceAccountName is not None and serviceAccountPass is not None and self.triggerChallenge:
            builder.setServiceAccount(serviceAccountName, serviceAccountPass)
        elif self.triggerChallenge:
            print("Trigger challenge enabled but no service account set!")
            self.triggerChallenge = False

        if configurationAttributes.containsKey("serviceaccountrealm"):
            serviceAccountRealm = configurationAttributes.get("serviceaccountrealm").getValue2()
            builder.setServiceAccountRealm(serviceAccountRealm)
            
        self.pi = builder.build()
        self.sessionIdservice = CdiUtil.bean(SessionIdService)

        print("privacyIDEA. init done")
        return True

    def authenticate(self, configurationAttributes, requestParameters, step):
        #print("Authenticate step={} with sendpass={} and triggerchallenge={}".format(step, self.sendPassword, self.triggerChallenge))
        fm = CdiUtil.bean(FacesMessages)
        fm.clear()
        fm.setKeepMessages()

        if self.pi is None:
            fm.add(FacesMessage.SEVERITY_ERROR, "Failed to communicate to privacyIDEA. Possible misconfiguration. Please have the administrator check the log files.")
            return False

        identity = CdiUtil.bean(Identity)

        if step == 1:
            credentials = identity.getCredentials()
            username = credentials.getUsername()
            password = credentials.getPassword()

            if username:
                if self.sendPassword:
                    response = self.pi.validateCheck(username, password)
                    if response:
                        # First check if what was entered is sufficient to log in
                        if response.getValue():
                            logged_in = self.login(username, password)
                            if logged_in:
                                self.addToSession("auth_success", True)
                            return logged_in
                        # If not, check if transaction was triggered
                        elif response.getTransactionID():
                            self.evaluateTriggeredChallenges(response, identity)
                    else:
                        print("privacyIDEA. Empty response from server")
                        fm.add(FacesMessage.SEVERITY_ERROR, "No response from the privacyIDEA Server. Please check the connection!")

                elif self.triggerChallenge:
                    response = self.pi.triggerChallenges(username)
                    if response is None:
                        fm.add(FacesMessage.SEVERITY_ERROR, "Failed to communicate to privacyIDEA. Possible misconfiguration. Please have the administrator check the log files.")
                        print("Service account misconfiguration or no response from the privacyIDEA server!")
                    elif response.getTransactionID():
                        self.evaluateTriggeredChallenges(response, identity)
                else:
                    # Setup for just OTP in second step
                    identity.setWorkingParameter("otp_available", "1")
                    identity.setWorkingParameter("transaction_message", "Please enter the OTP:")

                self.addToSession("currentUser", username)
                self.addToSession("currentPassword", password)

                return True

            else:
                #print("privacyIDEA. Username is empty")
                fm.add(FacesMessage.SEVERITY_ERROR, "Please enter a username!")

            return False
        else:
            # Get the user from step 1
            currentUser = self.getFromSession("currentUser")
            currentPassword = self.getFromSession("currentPassword")

            if currentUser and currentPassword:
                self.login(currentUser, currentPassword)
            else:
                print("privacyIDEA. No user found in session for second step")
                fm.add(FacesMessage.SEVERITY_ERROR, "Session data got lost. Please try to restart the authentication!")
                return False

            try:
                # Persist the mode between the script and the js
                mode = requestParameters.get("modeField")[0].strip()
                identity.setWorkingParameter("mode", mode)
            except TypeError:
                print("privacyIDEA. Mode not found in request parameters")

            txid = self.getFromSession("transaction_id")

            # If mode is push: poll for the transactionID to see if the user confirmed on the smartphone
            if mode == "push":
                if not txid:
                    print("privacyIDEA. Transaction ID not found in session, but it is mandatory for polling!")
                    fm.add(FacesMessage.SEVERITY_ERROR, "Your transaction id could not be found. Please try to restart the authentication!")
                    return False

                if self.pi.pollTransaction(txid):
                    # If polling is successful, the authentication has to be finished by a call to validateCheck
                    # with the username, NO otp and the transactionID
                    response = self.pi.validateCheck(currentUser, "", txid)
                    return response.getValue()

            elif mode == "otp":
                try:
                    otp = requestParameters.get("otp")[0]
                except TypeError:
                    print("privacyIDEA. Unable to obtain OTP from requestParameters, but it is required!")
                    fm.add(FacesMessage.SEVERITY_ERROR, "Your input could not be read. Please try to restart the authentication!")

                if otp:
                    # Either do validate/check with transaction id if there is one in the session or just with the input
                    if txid:
                        resp = self.pi.validateCheck(currentUser, otp, txid)
                    else:
                        resp = self.pi.validateCheck(currentUser, otp)

                    if resp:
                        return resp.getValue()
        return False

    def evaluateTriggeredChallenges(self, response, identity):
        identity.setWorkingParameter("transaction_message", response.getMessage())
        self.addToSession("transaction_id", response.getTransactionID())

        # Check if push is available
        tttList = response.getTriggeredTokenTypes()
        if tttList.contains("push"):
            identity.setWorkingParameter("push_available", "1")
            tttList.remove("push")

        # Check if an input field is needed for any other token type
        if tttList.size() > 0:
            identity.setWorkingParameter("otp_available", "1")

    def login(self, username, password):
        #print("Login with user={} and pass={}, verifyGluuPassword={}".format(username, password, self.verifyGluuPassword))
        authenticationService = CdiUtil.bean(AuthenticationService)
        if not self.disableGluuPass:
            logged_in = authenticationService.authenticate(username, password)
        else:
            logged_in = authenticationService.authenticate(username)
        
        return logged_in

    def addToSession(self, key, value):
        #print("addToSession: {}, {}".format(key, value))
        session = self.sessionIdservice.getSessionId()
        session.getSessionAttributes().put(key, value)
        self.sessionIdservice.updateSessionId(session)

    def getFromSession(self, key):
        #print("getFromSession: {}".format(key))
        session = self.sessionIdservice.getSessionId()
        return session.getSessionAttributes().get(key) if session else None

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        #print("prepareForStep {}, params={}".format(step, requestParameters))
        if step == 1: return True

        # Set the initial state for our template
        identity = CdiUtil.bean(Identity)
        identity.setWorkingParameter("mode", "otp")
        return True

    def getExtraParametersForStep(self, configurationAttributes, step):
        #print("getExtraParametersForStep {}".format(step))
        return Arrays.asList("transaction_message", "push_available", "otp_available", "mode")

    def getCountAuthenticationSteps(self, configurationAttributes):
        #print("getCountAuthenticationSteps")
        if self.getFromSession("auth_success"):
            #print("Auth success in session, returning 1")
            return 1
        else:
            #print("Auth success not in session, returning 2")
            return 2

    def getPageForStep(self, configurationAttributes, step):
        #print("getPageForStep {}".format(step))
        return "" if step == 1 else "/auth/privacyidea/privacyidea.xhtml"

    def getNextStep(self, configurationAttributes, requestParameters, step):
        #print("getNextStep {}".format(step))
        return -1

    def destroy(self, configurationAttributes):
        #print("destroy")
        return True

    def getApiVersion(self):
        #print("getApiVersion = {}".format(SCRIPT_API_VERSION))
        return GLUU_API_VERSION

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        #print("isValidAuthenticationMethod")
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        #print("getAlternativeAuthenticationMethod")
        return None

    def getAuthenticationMethodClaims(self, requestParameters):
        #print("getAuthenticationMethodClaims")
        return None

    def logout(self, configurationAttributes, requestParameters):
        #print("logout")
        return True
