# oxAuth is available under the MIT License (2008).
# See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Whispeak _ 2021
#
from base64 import b64decode

import json
import sys
import time
import logging
import re

from java.io import BufferedReader, InputStreamReader
from java.lang import String
from java.net import URI
from java.util import Arrays, Collections
from javax.faces.application import FacesMessage
from javax.faces.context import FacesContext
from org.apache.commons.io import IOUtils
from org.apache.http import HttpStatus
from org.apache.http.client.methods import HttpDelete, HttpGet, HttpPost
from org.apache.http.client.utils import URIBuilder
from org.apache.http.entity import ContentType
from org.apache.http.entity.mime import MultipartEntityBuilder
from org.apache.http.impl.client import HttpClientBuilder
from org.gluu.config.oxtrust import LdapOxPassportConfiguration
from org.gluu.jsf2.message import FacesMessages
from org.gluu.jsf2.service import FacesService
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.model.common import User
from org.gluu.oxauth.model.jwt import Jwt
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import AuthenticationService, UserService
from org.gluu.oxauth.service.common import EncryptionService
from org.gluu.oxauth.service.net import HttpService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service import CacheService
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)


SCRIPT_VERSION = 'whispeak_open_v1.py'


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, current_time_millis):
        self.current_time_millis = current_time_millis
        self.identity = CdiUtil.bean(Identity)

    ################################################################################
    # Gluu auxilliary configuration and status functions
    ################################################################################

    ################################################################################
    # Initialization functions

    def init(self, custom_script, configuration_attributes):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initialization start")
        log_format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'
        logging.basicConfig(format=log_format)
        self.logger.setLevel(logging.DEBUG)

        success = self._process_key_store_properties(configuration_attributes)

        self.http_client = HttpClientBuilder.create().build()

        if success:
            self.provider_key = "provider"
            self.passport_dn = self._get_passport_config_dn()
        else:
            self.logger.debug("Passport Not initialized")

        self.logger.debug("Initialization ok")

        return True

    def _get_passport_config_dn(self):
        file = open('/etc/gluu/conf/gluu.properties', 'r')
        for line in file:
            prop = line.split("=")
            if prop[0] == "oxpassport_ConfigurationEntryDN":
                prop.pop(0)
                break

        file.close()
        return "=".join(prop).strip()

    def _process_key_store_properties(self, configuration_attributes):
        file = configuration_attributes.get("KEY_STORE_FILE")
        password = configuration_attributes.get("KEY_STORE_PASSWORD")

        if file is not None and password is not None:
            file = file.getValue2()
            password = password.getValue2()

            if StringHelper.isNotEmpty(file) and StringHelper.isNotEmpty(password):
                self.key_store_file = file
                self.key_store_password = password
                return True

        self.logger.debug(
            "Properties key_store_file or key_store_password not found or empty")
        return False

    def _return_page(self, page, step):
        page = page.replace('//', '/')
        return page

    def _initialize_clean_config(self, configuration_attributes):

        self._reinitialize_cache()

        if configuration_attributes.containsKey("API_BASE_URL"):
            url = configuration_attributes.get("API_BASE_URL").getValue2()
            self.cache.put("API_BASE_URL", configuration_attributes.get(
                "API_BASE_URL").getValue2())
        if configuration_attributes.containsKey("API_APP_PATH"):
            path = configuration_attributes.get("API_APP_PATH").getValue2()
            self.cache.put("API_APP_PATH", path)
        if configuration_attributes.containsKey("API_KEY"):
            key = configuration_attributes.get("API_KEY").getValue2()
            self.cache.put("API_KEY", key)
        if configuration_attributes.containsKey("LOG_LEVEL"):
            log_level = configuration_attributes.get("LOG_LEVEL").getValue2()
            if log_level == "VERBOSE":
                def trace(frame, event, arg):
                    if event == "call":
                        filename = frame.f_code.co_filename
                        if filename == SCRIPT_VERSION:
                            function_name = frame.f_code.co_name
                            if function_name != "log":
                                print("Function {}", function_name)
                    return trace
                sys.settrace(trace)
            else:
                sys.settrace(None)

        if configuration_attributes.containsKey("MAX_NUMBER_OF_ERRORS_VERIFY"):
            number_of_errors_verify = configuration_attributes.get(
                "MAX_NUMBER_OF_ERRORS_VERIFY").getValue2()
            self.cache.put("MAX_NUMBER_OF_ERRORS_VERIFY",
                           int(number_of_errors_verify))
        else:
            self.cache.put("MAX_NUMBER_OF_ERRORS_VERIFY", 3)

        if configuration_attributes.containsKey("MAX_NUMBER_OF_ERRORS_FALLBACK"):
            number_of_errors_fallback = configuration_attributes.get(
                "MAX_NUMBER_OF_ERRORS_FALLBACK").getValue2()
            self.cache.put("MAX_NUMBER_OF_ERRORS_FALLBACK",
                           int(number_of_errors_fallback))
        else:
            self.cache.put("MAX_NUMBER_OF_ERRORS_FALLBACK", 0)

        if configuration_attributes.containsKey("CHECK_ONLY_USERNAME"):
            chek_domain = configuration_attributes.get(
                "CHECK_ONLY_USERNAME").getValue2()
            self.cache.put("CHECK_ONLY_USERNAME",
                           chek_domain)
        else:
            self.cache.put("CHECK_ONLY_USERNAME", False)

        if configuration_attributes.containsKey("SECOND_FACTOR"):
            second_factor = configuration_attributes.get(
                "SECOND_FACTOR").getValue2()
            self.logger.debug("Second factor is %s", second_factor)
            self.cache.put("SECOND_FACTOR", second_factor)
            self.identity.setWorkingParameter("show_password", second_factor)

        if configuration_attributes.containsKey("KEY_STORE_FILE"):
            self.logger.debug("Passport is enabled")
        else:
            self.cache.put("PASSPORT_DISABLED", True)
            self.logger.debug("Passport is disabled")

        self.identity.setWorkingParameter("show_oidc_panel", False)
        self.identity.setWorkingParameter("show_return_client_panel", False)
        self.identity.setWorkingParameter("external_providers", False)

        if not url or not path or not key:
            if not url:
                self.logger.error("Mandatory Property: API_BASE_URL")
            if not path:
                self.logger.error("Mandatory Property: API_APP_PATH")
            if not key:
                self.logger.error("Mandatory Property: API_KEY")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authConfigurationError")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "error.badConfiguration")
            return False
        self.cache.put(
            "ENDPOINT", "{url}/apps{path}".format(url=url, path=path))

        return True

    def _reinitialize_cache(self):
        self.logger.debug("Do Cache")
        self.cache = CdiUtil.bean(CacheService)
        self.cache.put("API_BASE_URL", "")
        self.cache.put("API_APP_PATH", "")
        self.cache.put("API_KEY", "")
        self.cache.put("ENDPOINT", "")
        self.cache.put("NEXT_STEP", "")
        self.cache.put("NO_IDENTIFICATION_STEP", False)
        self.cache.put("COUNT_AUTHENTICATION_STEPS", "")
        self.cache.put("TOKEN", "")
        self.cache.put("ASR_TEXT", "")
        self.cache.put("RETRY_ERROR", "")
        self.cache.put("MAX_NUMBER_OF_ERRORS_FALLBACK", "")
        self.cache.put("CHECK_ONLY_USERNAME", "")
        self.cache.put("MAX_NUMBER_OF_ERRORS_VERIFY", "")
        self.cache.put("ERROR_NUMBER", 0)
        self.cache.put("ERROR_NUMBER_VERIFY", 0)
        self.cache.put("FLOW", "")
        self.cache.put("PASSPORT_DISABLED", False)
        self.cache.put("SECOND_FACTOR", False)

    def getApiVersion(self):
        return 11

    def getAlternativeAuthenticationMethod(self, usage_type, configuration_attributes):

        ALTERNATIVE_ACR_VALUE = configuration_attributes.get(
            "ALTERNATIVE_ACR_VALUE").getValue2()
        self.logger.debug("Alternative acr value %s", ALTERNATIVE_ACR_VALUE)

        return ALTERNATIVE_ACR_VALUE

    def getExtraParametersForStep(self, configuration_attributes, step):
        return Arrays.asList(
            "username",
            "flow",
            "enroll_challenge",
            "external_providers",
            "selected_provider",
            "passport_user_profile",
            "whispeak_signature_id",
            "revocation_ui_link",
            "revocation_pwd",
            "show_password",
            "user_password",
            "user_profile_oidc"
        )

    def getCountAuthenticationSteps(self, configuration_attributes):

        steps = int(self.cache.get("COUNT_AUTHENTICATION_STEPS") or 7)
        self.logger.debug(
            "Total authentication count steps before jump %s", steps)
        steps = self._set_jump_steps(
            steps, True)
        self.logger.debug(
            "Total authentication count steps after jump %s", steps)

        return steps

    ################################################################################
    # Fallback on platform down

    def isValidAuthenticationMethod(self, usage_type, configuration_attributes):

        self.identity = CdiUtil.bean(Identity)

        if self.cache.get("flow"):
            if not self._isWhispeakAlive():
                return False

        return True

    def _isWhispeakAlive(self):
        self.logger.debug("Whispeak ENDPOINT %s", self.cache.get("ENDPOINT"))

        url = URI(self.cache.get("API_BASE_URL") + "/health")

        get_connection = HttpGet(url)

        try:
            http_service_response = self.http_client.execute(get_connection)
            if http_service_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                http_service_response.close()
                raise Exception()
            http_service_response.close()
        except Exception as exception:
            self.logger.error("Contact Whispeak Server FAILED %s", exception)
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authTimeout")
            return False
        finally:
            get_connection.releaseConnection()
        self.logger.debug("Whispeak Heartbeat Alive")
        return True

    ################################################################################
    # End lifecycle

    def destroy(self, configuration_attributes):
        self.logger.info("Destroy SUCCESS")
        return True

    def get_logout_external_url(self, configuration_attributes, request_parameters):
        return None

    def logout(self, configuration_attributes, request_parameters):
        return True

    ################################################################################
    # Gluu step management functions
    ################################################################################

    def _set_user_name_from_parameters(self):
        extra_parameters = ServerUtil.getFirstValue(FacesContext.getCurrentInstance(
        ).getExternalContext().getRequest().getParameterMap(), "extraParameters")

        if extra_parameters:
            username = json.loads(extra_parameters)["username"]
            self.logger.debug(
                "Username from extra_parameters is %s", username)
        else:
            username = ServerUtil.getFirstValue(FacesContext.getCurrentInstance(
            ).getExternalContext().getRequest().getParameterMap(), "username")
        self.logger.debug("Username from direct parameter is %s", username)

        if not username:
            return False

        self._get_user_flow(username)

        if self.cache.get("SECOND_FACTOR"):
            self.identity.setWorkingParameter("username", username)
        else:
            self.cache.put("NO_IDENTIFICATION_STEP", True)

        return True

    ################################################################################
    # Called before each step to retrieve xhtml page

    def getPageForStep(self, configuration_attributes, step):
        if step == 1:
            self._initialize_clean_config(configuration_attributes)
            self._set_user_name_from_parameters()

        return self._getPageForStep(step)

    def _getPageForStep(self, step):
        flow = self.cache.get("flow")
        enroll_challenge = self.identity.getWorkingParameter(
            "enroll_challenge")

        step = self._set_jump_steps(step)

        if step == 1:
            page = self._return_page(
                "/whispeak_open_identification.xhtml", step)

        if step == 2:
            if flow == "enroll":
                page = self._return_page(
                    "/whispeak_open_ask_enroll.xhtml", step)
            else:
                page = self._return_page(
                    "/whispeak_open_authentication_submit.xhtml", step)

        if step == 3:
            if flow == "enroll" and enroll_challenge:
                if enroll_challenge == "Reject":
                    page = self._return_page(
                        "/whispeak_open_passport_fallback.xhtml", step)
                else:
                    page = self._return_page(
                        "/whispeak_open_passport.xhtml", step)
            else:
                page = self._return_page(
                    "/whispeak_open_passport_loading.xhtml", step)

        if step == 4:
            page = self._return_page(
                "/whispeak_open_passport_loading.xhtml", step)

        if step == 5:
            page = self._return_page(
                "/whispeak_open_enrollment_submit.xhtml", step)

        if step == 6:
            page = self._return_page(
                "/whispeak_open_authentication_submit.xhtml", step)

        if step == 7:
            page = self._return_page(
                "/whispeak_open_revocation_data_show.xhtml", step)

        self.logger.debug("Page %s for Step %s", page, step)

        enroll_challenge = self.identity.getWorkingParameter(
            "enroll_challenge")
        return page

    ################################################################################
    # Called to know which step goes next

    def getNextStep(self, configuration_attributes, request_parameters, step):

        next_step = self.cache.get("NEXT_STEP")

        if next_step:
            self.cache.put("NEXT_STEP", "")
        else:
            next_step = -1

        self.logger.debug("Next step %s current step %s", next_step, step)

        return next_step

    ################################################################################
    # Called before each step to execute logic

    def prepareForStep(self, configuration_attributes, request_parameters, step):

        step = self._set_jump_steps(step)

        try:
            flow = self.cache.get("flow")
            self.logger.debug("Flow %s Step %s", flow, step)

            if step > 4 or (step == 2 and flow == "auth"):
                self._set_access_token_and_text(
                    self._get_access_token_and_text("enroll")
                    if flow == "enroll" and step == 5
                    else self._get_access_token_and_text("auth")
                )

            if (step > 2 or (step == 2 and flow == "auth")) and not self.cache.get("PASSPORT_DISABLED"):
                self.logger.debug("Preparing passport")
                self._prepare_passport()
        except Exception as exception:
            self.logger.error(
                "Exception in prepareForStep function, returning to step 1 %s", exception)
            self.cache.put("NEXT_STEP", 1)
            self._set_message_error(
                FacesMessage.SEVERITY_INFO, "login.send_restart")

        return True

    ################################################################################
    # Gluu authentication functions
    ################################################################################

    ################################################################################
    # Core gluu authentication

    def authenticate(self, configuration_attributes, request_parameters, step):
        self.logger.debug("Step %s", step)

        if self.cache.get("PASSPORT_DISABLED"):
            if not self._redirect_to_client_fallback(configuration_attributes, request_parameters):
                return False

        if not self._check_script_exec_in_order(request_parameters, step):
            return False

        step = self._set_jump_steps(step)

        step_ok = False

        try:
            self.cache.put("RETRY_ERROR", False)

            enroll_challenge = request_parameters.get(
                "loginForm:enroll_challenge")
            self.identity.setWorkingParameter(
                "enroll_challenge", enroll_challenge[0] if enroll_challenge is not None else None)

            step_ok = self.__class__.__dict__["_PersonAuthentication__step{step}".format(step=step)](
                self,
                request_parameters,
                step)

            count_authentication_steps = self.cache.get(
                "COUNT_AUTHENTICATION_STEPS")

            next_step = step + 1
            if step + 1 > count_authentication_steps:
                user = self.identity.getWorkingParameter("username")
                CdiUtil.bean(AuthenticationService).authenticate(user)
                self.logger.info(
                    "Flow is finished login user %s in gluu service, in step %s", user, step)
            else:
                self.logger.info(
                    "Flow is not finished going to next step: %s", next_step)

            if not step_ok:
                self.logger.warning("Step %s failed", step)
                if self.cache.get("RETRY_ERROR"):
                    current_error_number = self.cache.get("ERROR_NUMBER") + 1
                    self.cache.put("ERROR_NUMBER", current_error_number)
                    number_of_errors_fallback = self.cache.get(
                        "MAX_NUMBER_OF_ERRORS_FALLBACK")
                    self.logger.debug("Current nb of errors %s Fallback at nb of errors %s", self.cache.get(
                        "ERROR_NUMBER"), number_of_errors_fallback)
                    if current_error_number >= number_of_errors_fallback:
                        if self.cache.get("PASSPORT_DISABLED"):
                            self.identity.setWorkingParameter(
                                "show_return_client_panel", True)
                        else:
                            self.identity.setWorkingParameter(
                                "show_oidc_panel", True)
                else:
                    self.logger.warning(
                        "Non retriable error returning to step 1, RETRY_ERROR is %s", self.cache.get("RETRY_ERROR"))
                    self.cache.put("NEXT_STEP", 1)
                    self._set_message_error(
                        FacesMessage.SEVERITY_INFO, "login.send_restart")

        except Exception as exception:
            self.logger.error(
                "Exception in authentication function, returning to step 1 %s", exception)
            self.cache.put("NEXT_STEP", 1)
            self._set_message_error(
                FacesMessage.SEVERITY_INFO, "login.send_restart")

        return step_ok

    def _redirect_to_client_fallback(self, configuration_attributes, request_parameters):
        client_url = FacesContext.getCurrentInstance().getExternalContext(
        ).getRequestCookieMap().get("rp_origin_id").getValue()

        host = "auth.pre.whispeak.io"
        if bool(client_url) and not host in client_url:
            root_url = re.search(
                r"(https://[a-zA-Z\-\.]+)/.*", client_url).group(1)
            self.logger.debug("root_url %s", root_url)
            self.identity.setWorkingParameter("client_url", root_url)
        else:
            self.identity.setWorkingParameter(
                "client_url", configuration_attributes.get("fallback_redirect_url").getValue2())

        # Get enroll challenge response
        enroll_challenge_parameter = request_parameters.get(
            "loginForm:enroll_challenge")
        enroll_challenge = enroll_challenge_parameter[0] if enroll_challenge_parameter is not None else None

        rejected_enroll = enroll_challenge == "Reject"

        redirect_to_client = bool(ServerUtil.getFirstValue(
            request_parameters, "loginForm:redirect-to-client")) or rejected_enroll

        if bool(redirect_to_client):
            faces_service = CdiUtil.bean(FacesService)
            client_url = self.identity.getWorkingParameter(
                "client_url")
            if bool(client_url):
                self.logger.debug("Redirecting to %s", client_url)
                faces_service.redirectToExternalURL(client_url)
            else:
                self._setMessageError(
                    FacesMessage.SEVERITY_INFO, "login.restart")
                self.cache.put("NEXT_STEP", 1)
                self.logger.error("Not possible to get client URL, restarting")
                return False
        return True

    def _check_script_exec_in_order(self, request_parameters, step):
        origin_page_param = ServerUtil.getFirstValue(
            request_parameters, "loginForm:origin-page")

        if origin_page_param:
            expected_page = self._getPageForStep(step)

            origin_page = self._return_page(origin_page_param, step)
            self.logger.debug("origin_page %s", origin_page)
            self.logger.debug("expected_page %s", expected_page)

            if origin_page != expected_page:
                self._set_message_error(
                    FacesMessage.SEVERITY_INFO, "login.restart")
                self.cache.put("NEXT_STEP", 1)
                self.logger.error(
                    "origin_page and expected_page differ restart on step 1")
                return False
        return True

    def _set_jump_steps(self, step, back=False):
        if self.cache.get("NO_IDENTIFICATION_STEP"):
            step = self._jump(step, back, 1)
            self.logger.debug(
                "Jumping over first step, so updated to %s", step)
        if self.cache.get("PASSPORT_DISABLED") and 2 < step < 8:
            step = self._jump(step, back, 2)
            self.logger.debug(
                "Jumping over passport steps, so updated to %s", step)
        return step

    def _jump(self, step, back, amount):
        if back:
            return step - amount
        return step + amount

    ################################################################################
    # First step: user identification with email

    def __step1(self, request_parameters, step):

        credentials = self.identity.getCredentials()

        username = credentials.getUsername()
        if not username:
            return False

        user = self._get_user_flow(username)

        # ONLY FOR DEMO PURPPOSES
        # as we are already authenticating user here before voice to some extent, possibly insecure
        if self.cache.get("SECOND_FACTOR"):
            user_password = ServerUtil.getFirstValue(
                request_parameters, "loginForm:password") or credentials.getPassword()
            if StringHelper.isNotEmptyString(username) and StringHelper.isNotEmptyString(user_password):
                if not user or not user.getAttribute('userPassword'):
                    self.identity.setWorkingParameter(
                        "user_password", user_password)
                    return True
                authenticated = CdiUtil.bean(
                    AuthenticationService).authenticate(username, user_password)
                if not authenticated:
                    self.logger.info(
                        "Password missmatch for user %s", username)
                    self._set_message_error(
                        FacesMessage.SEVERITY_ERROR, "whispeak.login.2fa.passwordMissmatch")
                return authenticated
            return False

        return True

    def _get_user_flow(self, username):
        user_service = CdiUtil.bean(UserService)
        user = user_service.getUserByAttribute('mail',  username)
        whispeak_signature_id = ''

        self.identity.setWorkingParameter("username", username)

        if user:
            whispeak_signature_id = user.getAttribute('whispeakSignatureId')

        if not user or not whispeak_signature_id:
            self.logger.info(
                "User %s does not exist or is not enrolled, will be created", username)
            self.identity.setWorkingParameter("flow", "enroll")
            self.cache.put("flow", "enroll")
            self.cache.put("COUNT_AUTHENTICATION_STEPS", 7)
            self.logger.debug("Updated total steps to: %s",
                              self.cache.get("COUNT_AUTHENTICATION_STEPS"))
        else:
            self.logger.info(
                "User %s is already enrolled, proceed for authentication", username)
            self.identity.setWorkingParameter("flow", "auth")
            self.cache.put("flow", "auth")
            self.cache.put("COUNT_AUTHENTICATION_STEPS", 2)
            self.logger.debug("Updated total steps to: %s",
                              self.cache.get("COUNT_AUTHENTICATION_STEPS"))
        return user

    ################################################################################
    # Second step: enrollment challenge question, auth or passport

    def __step2(self, request_parameters, step):
        flow = self.identity.getWorkingParameter("flow")

        if flow == "auth":
            if self._check_and_activate_alternative_provider_selected(request_parameters):
                self.cache.put("COUNT_AUTHENTICATION_STEPS", 3)
                self.logger.debug("Updated total steps to: %s",
                                  self.cache.get("COUNT_AUTHENTICATION_STEPS"))
                redirect_result = self._redirect_oidc()
                return redirect_result

            login_voice = self._get_login_voice_and_set_text(
                request_parameters)
            if not login_voice:
                self.logger.warning(
                    "Authentication flow, voice is NOT present, retriable error")
                self.cache.put("RETRY_ERROR", True)
                return False
            else:
                self.logger.debug(
                    "Authentication flow, voice is present in request with size in bytes %s", (len(login_voice)))

            username = self.identity.getWorkingParameter("username")
            user_service = CdiUtil.bean(UserService)
            user = user_service.getUserByAttribute('mail',  username)

            whispeak_signature_id = user.getAttribute('whispeakSignatureId')
            logged_in = self._whispeak_voice(
                "auth", login_voice, whispeak_signature_id)
            if logged_in:
                user_password = self.identity.getWorkingParameter(
                    "user_password")
                if user_password:
                    user.setAttribute('userPassword', user_password)
                    user_service.updateUser(user)
            self.logger.info(
                "User %s is authenticated via voice in Whispeak", username)
            return logged_in

        else:
            enroll_challenge = self.identity.getWorkingParameter(
                "enroll_challenge")
            if enroll_challenge == "Reject":
                self.logger.debug("User does not want to enroll, fallback")
                self.cache.put("COUNT_AUTHENTICATION_STEPS", 4)
                self.logger.debug("Updated total steps to: %s",
                                  self.cache.get("COUNT_AUTHENTICATION_STEPS"))
            return True

    ################################################################################
    # Third step: passport redirect

    def __step3(self, request_parameters, step):

        flow = self.cache.get("flow")

        if flow == "enroll":
            self._check_and_activate_alternative_provider_selected(
                request_parameters)
            redirect_result = self._redirect_oidc()
            return redirect_result
        else:
            jwt_param = ServerUtil.getFirstValue(request_parameters, "user")
            return self._is_oidc_authenticated(jwt_param)

    ################################################################################
    # Fourth step: passport return, TOKEN processing

    def __step4(self, request_parameters, step):

        jwt_param = ServerUtil.getFirstValue(request_parameters, "user")
        user_profile_oidc = self._is_oidc_authenticated(jwt_param)
        self.identity.setWorkingParameter(
            'user_profile_oidc', user_profile_oidc)
        return self._is_oidc_authenticated(jwt_param)

    ################################################################################
    # Fifth step: enroll with passport fallback

    def __step5(self, request_parameters, step):

        redirect_result = self._adjust_fallback_steps_passport_and_redirect(
            request_parameters)
        if redirect_result:
            self.logger.info("redirects")
            return redirect_result

        self.logger.info("Processing voice enroll")

        whispeak_signature_id = self._whispeak_voice(
            "enroll", self._get_login_voice_and_set_text(request_parameters))

        if whispeak_signature_id:
            self.identity.setWorkingParameter(
                "whispeak_signature_id", whispeak_signature_id)

        authentication_result = whispeak_signature_id

        return authentication_result

    ################################################################################
    # Sixth step: verify enroll with passport fallback

    def __step6(self, request_parameters, step):

        redirect_result = self._adjust_fallback_steps_passport_and_redirect(
            request_parameters)
        if redirect_result:
            self.logger.info("redirects")
            return redirect_result

        self.logger.info("Processing voice enroll verification")

        whispeak_signature_id = self.identity.getWorkingParameter(
            "whispeak_signature_id")
        username = self.identity.getWorkingParameter("username")
        logged_in = self._whispeak_voice("auth", self._get_login_voice_and_set_text(
            request_parameters), whispeak_signature_id)
        if logged_in:
            user_service = CdiUtil.bean(UserService)
            user = user_service.getUserByAttribute('mail',  username)
            user_profile_oidc = self.identity.getWorkingParameter(
                'user_profile_oidc')
            if not user:
                user = self._create_user(
                    username, user_service, whispeak_signature_id, user_profile_oidc)
            else:
                self._update_user(user, user_service, user_profile_oidc)
            user.setAttribute('whispeakSignatureId', whispeak_signature_id)
            user.setAttribute('whispeakRevocationUiLink',
                              self.identity.getWorkingParameter("revocation_ui_link"))
            user.setAttribute('whispeakRevocationPwd',
                              self.identity.getWorkingParameter("revocation_pwd"))
            user_password = self.identity.getWorkingParameter("user_password")
            if user_password:
                user.setAttribute('userPassword', user_password)
            user_service.updateUser(user)
        else:
            current_error_number_verify = self.cache.get(
                "ERROR_NUMBER_VERIFY") + 1
            self.cache.put("ERROR_NUMBER_VERIFY", current_error_number_verify)
            max_number_of_errors_verify = self.cache.get(
                "MAX_NUMBER_OF_ERRORS_VERIFY")
            self.logger.debug("Current nb of errors %s Verify at nb of errors %s",
                              current_error_number_verify, max_number_of_errors_verify)
            if current_error_number_verify >= max_number_of_errors_verify:
                self.log
                ger.debug("Proceding to delete signature")
                self._delete_signature(whispeak_signature_id)
                self.cache.put("RETRY_ERROR", False)
                self._new_messages()
                self._set_message_error(
                    FacesMessage.SEVERITY_ERROR, "whispeak.login.signatureDoesNotExist")

        return logged_in

    ################################################################################
    # Seventh step: show revocation info and confirm
    def __step7(self, request_parameters, step):

        return True

    ################################################################################
    # Whispeak Functions
    ################################################################################

    def _adjust_fallback_steps_passport_and_redirect(self, request_parameters):
        if self._check_and_activate_alternative_provider_selected(request_parameters):
            self.cache.put("COUNT_AUTHENTICATION_STEPS", 4)
            self.cache.put("NEXT_STEP", 4)
            redirect_result = self._redirect_oidc()
            return redirect_result
        return False

    def _get_login_voice_and_set_text(self, request_parameters):

        login_voice_base64 = ServerUtil.getFirstValue(
            request_parameters, "loginForm:voiceBase64")

        if login_voice_base64:
            login_voice = self._base64_to_file(login_voice_base64)
        asr_text = ServerUtil.getFirstValue(
            request_parameters, "loginForm:asr-text-retry")
        self.logger.debug(
            "Retrieved from form ASR_TEXT of length %s", len(asr_text))
        if asr_text:
            self.identity.setWorkingParameter("asr_text", asr_text)

        if not login_voice:
            self.logger.warning(
                "Authentication flow, voice is NOT present in request so return false and keep step")
            self.cache.put("RETRY_ERROR", True)
            return False
        else:
            self.logger.debug("Size bytes of file %s", len(login_voice))

        return login_voice

    def _base64_to_file(self, login_voice_base64):
        if not login_voice_base64:
            return None

        voice_bytes = b64decode(login_voice_base64.encode('ascii'))

        return voice_bytes

    def _get_access_token_and_text(self, for_method):
        self.logger.info("Get Token for: %s", for_method)

        whispeak_service_url = "{endpoint}/{route}".format(
            endpoint=self.cache.get("ENDPOINT"), route=for_method)

        url = URI(whispeak_service_url)

        self.logger.debug("URL Token %s", url)
        get_connection = HttpGet(url)
        bearer = "Bearer {key}".format(key=self.cache.get("API_KEY"))
        self.logger.debug("Bearer Token %s", bearer)
        get_connection.setHeader("Authorization", bearer)

        try:
            http_get_response = self.http_client.execute(get_connection)
            http_response_entity = http_get_response.getEntity()
            http_response_content = http_response_entity.getContent()
            if http_get_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                self.logger.error("Whispeak Obtain Acces Token - SERVER resp NOT OK code %s",
                                  http_get_response.getStatusLine().getStatusCode())
                http_get_response.close()
                return None

            data = json.loads(IOUtils.toString(http_response_content, "UTF-8"))
            http_get_response.close()
            return data

        except Exception as e:
            self.logger.error("Whispeak Obtain Acces Token Exception %s", e)
            return None
        finally:
            get_connection.releaseConnection()

    def _delete_signature(self, whispeak_signature_id):

        whispeak_service_url = "{endpoint}/signatures/{whispeak_signature_id}".format(
            endpoint=self.cache.get("ENDPOINT"), whispeak_signature_id=whispeak_signature_id)

        url = URI(whispeak_service_url)
        self.logger.debug("URL Delete %s", url)
        get_connection = HttpDelete(url)
        bearer = "Bearer {key}".format(key=self.cache.get("API_KEY"))
        self.logger.debug("Bearer Delete, bearer %s", bearer)
        get_connection.setHeader("Authorization", bearer)

        try:
            http_delete_response = self.http_client.execute(get_connection)
            if http_delete_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                self.logger.error("Whispeak Delete signature - SERVER resp NOT OK code %s",
                                  http_delete_response.getStatusLine().getStatusCode())
                return False
            self.logger.info("Whispeak Delete signature code %s",
                             http_delete_response.getStatusLine().getStatusCode())
        except Exception as exception:
            self.logger.error(
                "Whispeak Delete Signature Exception %s", exception)
            return False
        finally:
            if http_delete_response:
                http_delete_response.close()
            get_connection.releaseConnection()

        return True

    def _set_access_token_and_text(self, data):
        if not data or not data['text']:
            self.logger.error("Not possible to get tokens")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authConfigurationError")
            return False
        self.cache.put("TOKEN", data['token'])
        self.cache.put("ASR_TEXT", data['text'])
        self.identity.setWorkingParameter("token", data['token'])
        self.identity.setWorkingParameter("asr_text", data['text'])
        return True

    def _whispeak_voice(self, operation, login_voice, whispeak_signature_id=None):

        whispeak_service_url = "{endpoint}/{operation}".format(
            endpoint=self.cache.get("ENDPOINT"), operation=operation)

        builder = URIBuilder(whispeak_service_url)
        url = builder.build()
        self.logger.debug("URL %s", url)
        http_service_request = HttpPost(url)

        try:
            token = self.cache.get("TOKEN")
            if not token:
                data = self._get_access_token_and_text(operation)
                token = data["token"]
            http_service_request.setHeader("Authorization", "Bearer " + token)
            self.logger.debug("Bearer %s", token)
            multipart_builder = MultipartEntityBuilder.create()
            multipart_builder.addBinaryBody(
                "file", login_voice, ContentType.APPLICATION_OCTET_STREAM, "gluu" + ".wav")
            if operation == "auth":
                self.logger.info("Whispeak Signature %s",
                                 whispeak_signature_id)
                multipart_builder.addTextBody(
                    "id", whispeak_signature_id, ContentType.TEXT_PLAIN)
            multipart = multipart_builder.build()
            http_service_request.setEntity(multipart)
            time_sent = time.time()
            http_service_response = self.http_client.execute(
                http_service_request)
            self.logger.info(
                "Whispeak API, received response in %ss", (time.time() - time_sent))

            response_body = self._response_content_entity(
                http_service_response)
            status_code = http_service_response.getStatusLine().getStatusCode()
            if status_code == HttpStatus.SC_OK:
                self.logger.info("Operation  %s SUCCEED with code %s",
                                 operation, http_service_response.getStatusLine())
                return True
            if status_code == HttpStatus.SC_CREATED:
                self.identity.setWorkingParameter(
                    "revocation_ui_link", "https://vault.whispeak.io/db13e6e7-dc86-4c8f-b8ad-0f3d3bfb9883/" + response_body["id"])
                self.identity.setWorkingParameter(
                    "revocation_pwd", response_body['revocation']['signature_secret_password'])
                return response_body["id"]
            if status_code == 404:
                self._remove_signature(whispeak_signature_id)
                return False
            self.cache.put("RETRY_ERROR", True)
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, self._whispeak_error_message(status_code))
            self.logger.warning(
                "Operation FAILED with code%s", http_service_response.getStatusLine())
            return False
        except Exception as exception:
            if http_service_response:
                self.logger.info("Operation FAILED with code %s",
                                 http_service_response.getStatusLine())
            self.logger.error("Whispeak Auth Exception %s", exception)
            return False
        finally:
            if http_service_response:
                http_service_response.close()
            http_service_request.releaseConnection()

    def _remove_signature(self, whispeak_signature_id):
        user_service = CdiUtil.bean(UserService)
        user = user_service.getUserByAttribute(
            'whispeakSignatureId', whispeak_signature_id)
        user.setAttribute('whispeakSignatureId', '')
        user.setAttribute('whispeakRevocationUiLink', '')
        user.setAttribute('whispeakRevocationPwd', '')
        user_service.updateUser(user)
        self.logger.info(
            "Removed non existent user signature from Gluu %s to force enrollment again (probably speaker secret was removed)", whispeak_signature_id)
        self.cache.put("NEXT_STEP", "1")
        self._set_message_error(
            FacesMessage.SEVERITY_ERROR, "whispeak.login.signatureDoesNotExist")

    def _whispeak_error_message(self, code):
        error_messages = {
            400: "whispeak.apiError.badRequest",
            401: "whispeak.apiError.unauthorized",
            403: "whispeak.apiError.invalidCredential",
            404: "whispeak.apiError.signatureNotFound",
            415: "whispeak.apiError.unsupportedAudioFile",
            419: "whispeak.apiError.voiceMissmatch",
            420: "whispeak.apiError.audioConstraintsFailed",
            430: "whispeak.apiError.invalidEnrollSignature"
        }
        return error_messages[code]

    ################################################################################
    # Passport functions
    ################################################################################

    def _prepare_passport(self):
        if not self.identity.getWorkingParameter("external_providers"):
            self.registered_providers = self._parse_provider_configs()
            self.identity.setWorkingParameter(
                "external_providers", json.dumps(self.registered_providers))

    def _get_passport_redirect_url(self, provider):

        self.logger.debug("Prepare passport for Provider %s", provider)

        # provider is assumed to exist in self.registered_providers
        url = None

        faces_context = CdiUtil.bean(FacesContext)
        token_endpoint = "https://%s/passport/TOKEN" % faces_context.getExternalContext().getRequest().getServerName()

        http_service = CdiUtil.bean(HttpService)
        http_client = http_service.getHttpsClient()

        self.logger.debug(
            "Obtaining TOKEN from passport at %s", token_endpoint)
        resultResponse = http_service.executeGet(
            http_client, token_endpoint, Collections.singletonMap("Accept", "text/json"))
        http_response = resultResponse.getHttpResponse()
        message_bytes = http_service.getResponseContent(http_response)

        response = http_service.convertEntityToString(message_bytes)
        self.logger.debug("Response Code %s",
                          http_response.getStatusLine().getStatusCode())
        if not http_response.getStatusLine().getStatusCode() == HttpStatus.SC_OK:
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "passport.unavailable")
        token_obj = json.loads(response)
        if 'token_' in token_obj:
            url = "/passport/auth/%s/%s" % (provider, token_obj["token_"])
        return url

    def _check_and_activate_alternative_provider_selected(self, request_parameters):
        provider = ServerUtil.getFirstValue(
            request_parameters, "loginForm:provider")
        if not provider:
            return False
        if not hasattr(self, 'registered_providers'):
            self.registered_providers = self.parseProviderConfigs()
        is_configured_provider = len(
            [prvd for prvd in self.registered_providers if next(iter(prvd)) == provider]) > 0

        if is_configured_provider:
            # it's a recognized external IDP
            self.identity.setWorkingParameter("selected_provider", provider)
            return True

        return False

    def _redirect_oidc(self):
        provider = self.identity.getWorkingParameter("selected_provider")
        if not provider:
            return False
        url = self._get_passport_redirect_url(provider)
        if not url:
            return False
        self.logger.info("Redirecting user to OIDC url: %s", url)
        self.identity.setWorkingParameter("selected_provider", None)
        faces_service = CdiUtil.bean(FacesService)
        faces_service.redirectToExternalURL(url)
        return True

    def _is_oidc_authenticated(self, jwt_param):

        # Parse JWT and validate
        self.logger.info("Checking user OIDC TOKEN")
        jwt = Jwt.parse(jwt_param)
        (user_profile) = self._get_user_profile(jwt)
        if user_profile is None:
            return False

        auth_step1_username = self.identity.getWorkingParameter("username")

        if not self._validate_username_oidc(auth_step1_username, user_profile):
            self.logger.error(
                "FAIL not possible to verify username returns false")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authOidcMissmatch")
            return False
        return user_profile

    def _validate_username_oidc(self, auth_step1_username, user_profile):

        oidc_username = user_profile["mail"][0]

        if self.cache.get("CHECK_ONLY_USERNAME"):
            auth_step1_username = auth_step1_username.split("@")[0]
            oidc_username = oidc_username.split("@")[0]

        self.logger.debug("Validate username matches with thirdparty username")

        if oidc_username != auth_step1_username:
            self.logger.warning(
                "Usernames from OIDC does not match username from auth step 1")
            return False
        return True

    def _get_user_profile(self, jwt):
        jwt_claims = jwt.getClaims()
        user_profile_json = None
        user_profile_json = CdiUtil.bean(EncryptionService).decrypt(
            jwt_claims.getClaimAsString("data"))
        user_profile = json.loads(user_profile_json)
        return user_profile

    def _parse_provider_configs(self):
        registered_providers = []
        registered_providers = self._parse_all_providers()
        to_remove = []
        for provider in registered_providers:
            provider = list(provider.values())[0]
            if provider["type"] == "saml":
                to_remove.append(provider)
            else:
                provider["saml"] = False
        for provider in to_remove:
            registered_providers.pop(provider)
        self.logger.debug("Configured providers: %s", registered_providers)

        return registered_providers

    def _parse_all_providers(self):
        registered_providers = []
        entry_manager = CdiUtil.bean(PersistenceEntryManager)
        config = LdapOxPassportConfiguration()
        config = entry_manager.find(
            config.getClass(), self.passport_dn).getPassportConfiguration()
        config = config.getProviders() if config is not None else config
        if config is not None and len(config) > 0:
            for prvdetails in config:
                if prvdetails.isEnabled():
                    registered_providers.append({prvdetails.getId():
                                                 {
                        "id": prvdetails.getId(),
                        "emailLinkingSafe": prvdetails.isEmailLinkingSafe(),
                        "requestForEmail": prvdetails.isRequestForEmail(),
                        "logo_img": prvdetails.getLogoImg(),
                        "displayName": prvdetails.getDisplayName(),
                        "type": prvdetails.getType(),
                    }
                    })
        return registered_providers

    ################################################################################
    # Generic Auxiliary functions
    ################################################################################

    def _create_user(self, user_email, user_service, signature_id=None, profile=None, user_password=None):
        new_user = User()

        username = user_email.split("@")[0]
        new_user.setAttribute("uid", user_email, True)
        new_user.setAttribute("givenName", username, True)
        new_user.setAttribute("displayName", username, True)
        new_user.setAttribute("sn", "-", True)
        new_user.setAttribute("mail", user_email, True)
        new_user.setAttribute("gluuStatus", "active", True)
        new_user.setAttribute("whispeakSignatureId", signature_id)
        new_user.setAttribute("password", user_password)

        if profile:
            self._fill_user(new_user, profile)

        new_user = user_service.addUser(new_user, True)

        return new_user

    def _update_user(self, user, user_service, profile):
        self._fill_user(user, profile)
        user_service.updateUser(user)

    def _fill_user(self, user, profile):

        for attr in profile:
            if attr != self.provider_key:
                values = profile[attr]
                user.setAttribute(attr, values)
                if attr == "mail":
                    ox_trust_mails = []
                    for mail in values:
                        ox_trust_mails.append(
                            '{"value":"{mail}","primary":false}')
                    user.setAttribute("oxTrustEmail", ox_trust_mails)

    def _set_message_error(self, severity, msg):
        if not hasattr(self, 'facesMessages'):
            self.facesMessages = CdiUtil.bean(FacesMessages)
        error_message = String.format("#{msgs['%s']}", msg)
        self.logger.debug("Error message to be returned %s", error_message)
        self.facesMessages.add(severity, error_message)

    def _new_messages(self):
        if hasattr(self, 'facesMessages'):
            self.facesMessages.clear()
        return CdiUtil.bean(FacesMessages)

    def _response_content_entity(self, http_service_response):
        input_stream = http_service_response.getEntity().getContent()
        reader = BufferedReader(InputStreamReader(input_stream, "UTF-8"), 8)
        string_buffer = ""
        line = reader.readLine()
        while line is not None:
            string_buffer = string_buffer + line.encode('utf-8') + "\n"
            line = reader.readLine()
        return json.loads(string_buffer)
