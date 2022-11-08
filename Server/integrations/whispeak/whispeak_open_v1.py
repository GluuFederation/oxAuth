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
from org.gluu.service import CacheService
from org.gluu.oxauth.service.common import EncryptionService
from org.gluu.oxauth.service.net import HttpService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


SCRIPT_VERSION = 'whispeak_open_v1.py'


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, current_time_millis):
        self.current_time_millis = current_time_millis

    ################################################################################
    # Gluu auxiliary configuration and status functions
    ################################################################################

    ################################################################################
    # Initialization functions

    def init(self, custom_script, configuration_attributes):
        self.logger = logging.getLogger(__name__)
        log_format = '%(levelname)s - [%(filename)s:%(lineno)s - %(funcName)20s()] - %(message)s'
        logging.basicConfig(format=log_format)
        self.logger.setLevel(logging.INFO)

        self.logger.info("Going to Setting log level")
        log_level = configuration_attributes.get("LOG_LEVEL")
        if log_level is not None:
            log_level_value = log_level.getValue2()
            self.logger.info("Setting log level %s", log_level_value)
            self.logger.setLevel(logging.getLevelName(log_level_value))
            if log_level_value == "DEBUG":
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

        success = self._process_key_store_properties(configuration_attributes)

        if success:
            self.provider_key = "provider"
            self.passport_dn = self._get_passport_config_dn()
            self.passport_enabled = True
        else:
            self.logger.debug("Passport Not initialized")
            self.passport_enabled = False
        self.logger.debug(
            "Initialization ok, passport enabled status %s", success)
        self._set_configuration_attributes(configuration_attributes)

        self.storage_working_parameters = True
        self.variable_debugging = False
        return True

    def _put(self, key, variable):
        if self.storage_working_parameters or (key in self._getWorkingParameters()):
            if self.variable_debugging:
                self.logger.debug(
                    "Put variable \"%s\" in working parameters with key \"%s\"", variable, key)
            CdiUtil.bean(Identity).setWorkingParameter(key, variable)
        else:
            unique_key = CdiUtil.bean(
                Identity).getSessionId().getId() + "-" + key
            if self.variable_debugging:
                self.logger.debug(
                    "Put variable \"%s\" in cache with key \"%s\"", variable, unique_key)
            CdiUtil.bean(CacheService).put(unique_key, variable)

    def _get(self, key):
        if self.storage_working_parameters or (key in self._getWorkingParameters()):
            variable = CdiUtil.bean(Identity).getWorkingParameter(key)
            if self.variable_debugging:
                self.logger.debug(
                    "Get variable \"%s\" from working parameters with key \"%s\"", variable, key)
            return variable
        else:
            unique_key = CdiUtil.bean(
                Identity).getSessionId().getId() + "-" + key
            variable = CdiUtil.bean(CacheService).get(unique_key)
            if self.variable_debugging:
                self.logger.debug(
                    "Get variable \"%s\" from cache with key \"%s\"", variable, unique_key)
            return variable

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

    def _set_configuration_attributes(self, configuration_attributes):
        if configuration_attributes.containsKey("API_BASE_URL"):
            url = configuration_attributes.get("API_BASE_URL").getValue2()
            self.api_base_url = configuration_attributes.get(
                "API_BASE_URL").getValue2()
        if configuration_attributes.containsKey("API_APP_PATH"):
            path = configuration_attributes.get("API_APP_PATH").getValue2()
            self.api_app_path = path
        if configuration_attributes.containsKey("API_KEY"):
            api_key = configuration_attributes.get("API_KEY").getValue2()
            self.api_key = api_key

        if configuration_attributes.containsKey("FALLBACK_RETURN_HOST"):
            fallback_return_host = configuration_attributes.get(
                "FALLBACK_RETURN_HOST").getValue2()
            self.fallback_return_host = fallback_return_host
        else:
            self.fallback_return_host = "auth.whispeak.io"

        if configuration_attributes.containsKey("MAX_NUMBER_OF_ERRORS_VERIFY"):
            number_of_errors_verify = configuration_attributes.get(
                "MAX_NUMBER_OF_ERRORS_VERIFY").getValue2()
            self.max_number_of_errors_verify = int(number_of_errors_verify)
        else:
            self.max_number_of_errors_verify = 3

        if configuration_attributes.containsKey("MAX_NUMBER_OF_ERRORS_FALLBACK"):
            number_of_errors_fallback = configuration_attributes.get(
                "MAX_NUMBER_OF_ERRORS_FALLBACK").getValue2()
            self.max_number_of_errors_fallback = int(number_of_errors_fallback)
        else:
            self.max_number_of_errors_fallback = 0

        if configuration_attributes.containsKey("CHECK_ONLY_USERNAME"):
            check_domain = configuration_attributes.get(
                "CHECK_ONLY_USERNAME").getValue2()
            self.check_only_username = check_domain
        else:
            self.check_only_username = False

        if configuration_attributes.containsKey("SECOND_FACTOR"):
            second_factor = configuration_attributes.get(
                "SECOND_FACTOR").getValue2()
            self.logger.debug("Second factor is %s", second_factor)
            self.second_factor = second_factor
        else:
            self.second_factor = False

        if not url or not path or not api_key:
            if not url:
                self.logger.error("Mandatory Property: API_BASE_URL")
            if not path:
                self.logger.error("Mandatory Property: API_APP_PATH")
            if not api_key:
                self.logger.error("Mandatory Property: API_KEY")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authConfigurationError")
            return False
        self.endpoint = "{url}/apps{path}".format(url=url, path=path)

    def _initialize_clean_config(self, configuration_attributes):

        self._reinitialize_storage()

        self._put("show_password", self.second_factor)
        self._put("show_oidc_panel", False)
        self._put("show_return_client_panel", False)
        self._put("external_providers", False)

        return True

    def _reinitialize_storage(self):
        self.logger.debug("Clean Working Parameters")
        for key in self._getWorkingParameters():
            self._put(key, None)
        for key in self._getStorage():
            self._put(key, None)

    def _print_storage(self):
        all_storage = self._getWorkingParameters() + self._getStorage()
        self.logger.debug(all_storage)
        for key in all_storage:
            self._get(key)

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getAlternativeAuthenticationMethod(self, usage_type, configuration_attributes):
        if configuration_attributes.containsKey("ALTERNATIVE_ACR_VALUE"):
            ALTERNATIVE_ACR_VALUE = configuration_attributes.get(
                "ALTERNATIVE_ACR_VALUE").getValue2()
            self.logger.debug("Alternative acr value %s",
                              ALTERNATIVE_ACR_VALUE)

            return ALTERNATIVE_ACR_VALUE
        return False

    def getExtraParametersForStep(self, configuration_attributes, step):
        # Used in xhtml pages
        parameters = self._getWorkingParameters()
        # Used internally in script
        if self.storage_working_parameters:
            parameters = Arrays.asList(
                self._getWorkingParameters() + self._getStorage())
        else:
            parameters = Arrays.asList(self._getWorkingParameters())
        return parameters

    def _getStorage(self):
        storage = ["username",
                   "selected_provider",
                   "passport_user_profile",
                   "whispeak_signature_id",
                   "user_password",
                   "user_profile_oidc",
                   "retry_error",
                   "no_identification_step",
                   "error_number",
                   "error_number_verify",
                   "count_authentication_steps",
                   "token",
                   "next_step",
                   "username_from_parameters"]
        return storage

    def _getWorkingParameters(self):
        parameters = ["flow",
                      "enroll_challenge",
                      "external_providers",
                      "asr_text",
                      "revocation_ui_link",
                      "revocation_pwd",
                      "show_password"]
        return parameters

    def getCountAuthenticationSteps(self, configuration_attributes):
        steps = int(self._get(
            "count_authentication_steps") or 7)
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
        if self._get("flow"):
            if not self._isWhispeakAlive():
                return False

        return True

    def _isWhispeakAlive(self):
        self.logger.debug("Whispeak ENDPOINT %s", self.endpoint)

        url = URI(self.api_base_url + "/health")

        get_connection = HttpGet(url)

        try:

            http_service_response = HttpClientBuilder.create().build().execute(get_connection)
            if http_service_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                http_service_response.close()
                raise Exception()
            http_service_response.close()
        except Exception as e:
            self.logger.error("Contact Whispeak Server FAILED %s", str(e))
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
        username = self._get_user_name_from_request()

        if username is None:
            username = self._get(
                "username_from_parameters")
            if username is None:
                return False
        else:
            self._put("username_from_parameters", username)

        self._set_user_and_flow(username)

        if not self.second_factor and username:
            self.logger.debug("No identification step will be shown")
            self._put("no_identification_step", True)

        return True

    def _get_user_name_from_request(self):
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

        return username

    ################################################################################
    # Called before each step to retrieve xhtml page

    def getPageForStep(self, configuration_attributes, step):
        if CdiUtil.bean(Identity).getSessionId():
            # Session is initialized
            flow = self._get("flow")
            enroll_challenge = self._get(
                "enroll_challenge")
            step = self._set_jump_steps(step)
        else:
            username = self._get_user_name_from_request()
            self.logger.debug("username is \"%s\"", username)
            if username and not self.second_factor:
                step = step + 1
                flow = "enroll"
                user = CdiUtil.bean(UserService).getUserByAttribute(
                    'mail',  username)
                if user:
                    if user.getAttribute('whispeakSignatureId'):
                        flow = "auth"

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

        return page

    ################################################################################
    # Called to know which step goes next

    def getNextStep(self, configuration_attributes, request_parameters, step):

        next_step = self._get("next_step")

        if next_step:
            self._put("next_step", "")
        else:
            next_step = -1

        self.logger.debug("Next step %s current step %s", next_step, step)

        return next_step

    ################################################################################
    # Called before each step to execute logic

    def prepareForStep(self, configuration_attributes, request_parameters, step):
        self.logger.debug(
            "Get session id prepare for step \"%s\" data \"%s\"", CdiUtil.bean(Identity).getSessionId().getId(), CdiUtil.bean(Identity).getSessionId().getSessionAttributes())

        if step == 1:
            username_from_parameters = self._get(
                "username_from_parameters")
            self._initialize_clean_config(configuration_attributes)
            if username_from_parameters is not None:
                self._put("username_from_parameters", username_from_parameters)
            self._set_user_name_from_parameters()

        step = self._set_jump_steps(step)

        try:
            flow = self._get("flow")
            self.logger.debug("Flow %s Step %s", flow, step)

            if step > 4 or (step == 2 and flow == "auth"):
                self._set_access_token_and_text(
                    self._get_access_token_and_text("enroll")
                    if flow == "enroll" and step == 5
                    else self._get_access_token_and_text("auth")
                )

            if (step > 2 or (step == 2 and flow == "auth")) and self.passport_enabled:
                self.logger.debug("Preparing passport")
                self._prepare_passport()
        except Exception as e:
            self.logger.error(
                "Exception in prepareForStep function, returning to step 1 %s", str(e))
            self._put("next_step", 1)
            self._set_message_error(
                FacesMessage.SEVERITY_INFO, "login.send_restart", False)

        return True

    ################################################################################
    # Gluu authentication functions
    ################################################################################

    ################################################################################
    # Core gluu authentication

    def authenticate(self, configuration_attributes, request_parameters, step):

        self.logger.debug(
            "Get session id \"%s\" data \"%s\"", CdiUtil.bean(Identity).getSessionId().getId(), CdiUtil.bean(Identity).getSessionId().getSessionAttributes())
        if self.variable_debugging:
            self._print_storage()
        self.logger.debug("Step %s", step)

        if not self.passport_enabled:
            if not self._redirect_to_client_fallback(configuration_attributes, request_parameters):
                return False

        if not self._check_script_exec_in_order(request_parameters, step):
            return False

        step = self._set_jump_steps(step)
        step_ok = False

        try:
            self._put("retry_error", False)

            enroll_challenge = request_parameters.get(
                "loginForm:enroll_challenge")
            self._put("enroll_challenge",
                      enroll_challenge[0] if enroll_challenge is not None else None)

            step_ok = self.__class__.__dict__["_PersonAuthentication__step{step}".format(step=step)](
                self,
                request_parameters,
                step)

            count_authentication_steps = self._get(
                "count_authentication_steps")

            self.logger.info("Step %s result is %s", step, step_ok)

            if step_ok:
                if step + 1 > count_authentication_steps:
                    user = self._get("username")
                    CdiUtil.bean(AuthenticationService).authenticate(user)
                    self.logger.info(
                        "Flow is finished login user %s in gluu service, in step %s", user, step)
            else:
                self.logger.warning("Step %s failed", step)
                if self._get("retry_error"):
                    current_error_number = self._get(
                        "error_number") or 0
                    current_error_number = current_error_number + 1
                    self._put("error_number", current_error_number)
                    number_of_errors_fallback = self.max_number_of_errors_fallback
                    self.logger.debug("Current nb of errors %s Fallback at nb of errors %s", self._get(
                        "error_number"), number_of_errors_fallback)
                    if current_error_number >= number_of_errors_fallback:
                        if not self.passport_enabled:
                            self._put("show_return_client_panel", True)
                        else:
                            self._put("show_oidc_panel", True)
                else:
                    self.logger.warning(
                        "Non retryable error returning to step 1, retry_error is %s", self._get("retry_error"))
                    self._put("next_step", 1)
                    self._set_message_error(
                        FacesMessage.SEVERITY_INFO, "login.send_restart", False)

        except Exception as e:
            self.logger.error(
                "Exception in authentication function, returning to step 1 %s", str(e))
            self._put("next_step", 1)
            self._set_message_error(
                FacesMessage.SEVERITY_INFO, "login.send_restart", False)

        if self.variable_debugging:
            self._print_storage()
        return step_ok

    def _redirect_to_client_fallback(self, configuration_attributes, request_parameters):
        client_url = FacesContext.getCurrentInstance().getExternalContext(
        ).getRequestCookieMap().get("rp_origin_id").getValue()

        host = self.fallback_return_host
        if bool(client_url) and not host in client_url:
            fallback_return_url = re.search(
                r"(https://[a-zA-Z\-\.]+)/.*", client_url).group(1)
        else:
            if configuration_attributes.containsKey("FALLBACK_REDIRECT_URL"):
                fallback_return_url = configuration_attributes.get(
                    "FALLBACK_REDIRECT_URL").getValue2()
            else:
                fallback_return_url = host
        self.logger.debug("fallback_return_url %s", fallback_return_url)
        self._put("client_url", fallback_return_url)

        # Get enroll challenge response
        enroll_challenge_parameter = request_parameters.get(
            "loginForm:enroll_challenge")
        enroll_challenge = enroll_challenge_parameter[0] if enroll_challenge_parameter is not None else None

        rejected_enroll = enroll_challenge == "Reject"

        redirect_to_client = bool(ServerUtil.getFirstValue(
            request_parameters, "loginForm:redirect-to-client")) or rejected_enroll

        if bool(redirect_to_client):
            client_url = self._get(
                "client_url")
            if bool(client_url):
                self.logger.debug("Redirecting to %s", client_url)
                CdiUtil.bean(FacesService).redirectToExternalURL(client_url)
            else:
                self._set_message_error(
                    FacesMessage.SEVERITY_INFO, "login.restart", False)
                self._put("next_step", 1)
                self.logger.error("Not possible to get client URL, restarting")
                return False
        return True

    def _check_script_exec_in_order(self, request_parameters, step):
        origin_page_param = ServerUtil.getFirstValue(
            request_parameters, "loginForm:origin-page")

        if origin_page_param:
            expected_page = self.getPageForStep(None, step)

            origin_page = self._return_page(origin_page_param, step)
            self.logger.debug("origin_page %s", origin_page)
            self.logger.debug("expected_page %s", expected_page)

            if origin_page != expected_page:
                self._set_message_error(
                    FacesMessage.SEVERITY_INFO, "login.restart", False)
                self._put("next_step", 1)
                self.logger.error(
                    "origin_page and expected_page differ restart on step 1")
                return False
        return True

    def _set_jump_steps(self, step, back=False):
        if self._get("no_identification_step"):
            step = self._jump(step, back, 1)
            self.logger.debug(
                "Jumping over first step, so updated to %s", step)
        if (not self.passport_enabled) and 2 < step < 8:
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

        credentials = CdiUtil.bean(Identity).getCredentials()

        username = credentials.getUsername()
        if not username:
            return False

        user = self._set_user_and_flow(username)

        # ONLY FOR DEMO PURPOSES
        # as we are already authenticating user here before voice to some extent, possibly insecure
        if self.second_factor:
            user_password = ServerUtil.getFirstValue(
                request_parameters, "loginForm:password") or credentials.getPassword()
            if StringHelper.isNotEmptyString(username) and StringHelper.isNotEmptyString(user_password):
                if not user or not user.getAttribute('userPassword'):
                    self._put("user_password", user_password)
                    return True
                authenticated = CdiUtil.bean(AuthenticationService).authenticate(
                    username, user_password)
                if not authenticated:
                    self.logger.info(
                        "Password mismatch for user %s", username)
                    self._set_message_error(
                        FacesMessage.SEVERITY_ERROR, "whispeak.login.2fa.passwordMismatch")
                return authenticated
            return False

        return True

    def _set_user_and_flow(self, username):
        user = CdiUtil.bean(UserService).getUserByAttribute('mail',  username)
        whispeak_signature_id = ''

        self._put("username", username)

        if user:
            whispeak_signature_id = user.getAttribute('whispeakSignatureId')

        if not user or not whispeak_signature_id:
            self.logger.info(
                "User %s does not exist or is not enrolled, will be created", username)
            self._put("flow", "enroll")
            self._put("count_authentication_steps", 7)
            self.logger.debug("Updated total steps to: %s",
                              self._get("count_authentication_steps"))
        else:
            self.logger.info(
                "User %s is already enrolled, proceed for authentication", username)
            self._put("flow", "auth")
            self._put("count_authentication_steps", 2)
            self.logger.debug("Updated total steps to: %s",
                              self._get("count_authentication_steps"))
        return user

    ################################################################################
    # Second step: enrollment challenge question, auth or passport

    def __step2(self, request_parameters, step):
        flow = self._get("flow")

        if flow == "auth":
            if self._check_and_activate_alternative_provider_selected(request_parameters):
                self._put("count_authentication_steps", 3)
                self.logger.debug("Updated total steps to: %s",
                                  self._get("count_authentication_steps"))
                redirect_result = self._redirect_oidc()
                return redirect_result

            login_voice = self._get_login_voice_and_set_text(
                request_parameters)
            if not login_voice:
                self.logger.warning(
                    "Authentication flow, voice is NOT present, retryable error")
                self._put("retry_error", True)
                return False
            else:
                self.logger.debug(
                    "Authentication flow, voice is present in request with size in bytes %s", (len(login_voice)))

            username = self._get("username")
            user = CdiUtil.bean(UserService).getUserByAttribute(
                'mail',  username)

            whispeak_signature_id = user.getAttribute('whispeakSignatureId')
            logged_in = self._whispeak_voice(
                "auth", login_voice, whispeak_signature_id)
            if logged_in:
                user_password = self._get(
                    "user_password")
                if user_password:
                    user.setAttribute('userPassword', user_password)
                    CdiUtil.bean(UserService).updateUser(user)
            self.logger.info(
                "User %s is authenticated via voice in Whispeak", username)
            return logged_in

        else:
            enroll_challenge = self._get(
                "enroll_challenge")
            if enroll_challenge == "Reject":
                self.logger.debug("User does not want to enroll, fallback")
                if self.passport_enabled:
                    self._put("count_authentication_steps", 4)
                else:
                    self._put("count_authentication_steps", 3)
                self.logger.debug("Updated total steps to: %s",
                                  self._get("count_authentication_steps"))
            return True

    ################################################################################
    # Third step: passport redirect

    def __step3(self, request_parameters, step):

        flow = self._get("flow")

        if flow == "enroll":
            self._check_and_activate_alternative_provider_selected(
                request_parameters)
            redirect_result = self._redirect_oidc()
            return redirect_result

        jwt_param = ServerUtil.getFirstValue(request_parameters, "user")
        return self._is_oidc_authenticated(jwt_param)

    ################################################################################
    # Fourth step: passport return, token processing

    def __step4(self, request_parameters, step):

        jwt_param = ServerUtil.getFirstValue(request_parameters, "user")
        user_profile_oidc = self._is_oidc_authenticated(jwt_param)
        self.logger.debug(
            "user_profile_oidc when retrieved \"%s\"", user_profile_oidc)
        if user_profile_oidc:
            self.logger.debug("Saving user profile")
            self._put('user_profile_oidc', user_profile_oidc)
            return True
        return False

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
            self._put("whispeak_signature_id", whispeak_signature_id)

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

        whispeak_signature_id = self._get(
            "whispeak_signature_id")
        username = self._get("username")
        logged_in = self._whispeak_voice("auth", self._get_login_voice_and_set_text(
            request_parameters), whispeak_signature_id)
        if logged_in:
            user = CdiUtil.bean(UserService).getUserByAttribute(
                'mail',  username)
            user_profile_oidc = self._get(
                'user_profile_oidc')
            if not user:
                user = self._create_user(
                    username, whispeak_signature_id, user_profile_oidc)
            else:
                self._update_user(user, user_profile_oidc)
            user.setAttribute('whispeakSignatureId', whispeak_signature_id)
            user.setAttribute('whispeakRevocationUiLink',
                              self._get("revocation_ui_link"))
            user.setAttribute('whispeakRevocationPwd',
                              self._get("revocation_pwd"))
            user_password = self._get("user_password")
            if user_password:
                user.setAttribute('userPassword', user_password)
            CdiUtil.bean(UserService).updateUser(user)
        else:
            current_error_number_verify = self._get(
                "error_number_verify") + 1
            self._put("error_number_verify", current_error_number_verify)
            max_number_of_errors_verify = self.max_number_of_errors_verify
            self.logger.debug("Current nb of errors %s Verify at nb of errors %s",
                              current_error_number_verify, max_number_of_errors_verify)
            if current_error_number_verify >= max_number_of_errors_verify:
                self.logger.debug("Proceeding to delete signature")
                self._delete_signature(whispeak_signature_id)
                self._put("retry_error", False)
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
            self._put("count_authentication_steps", 4)
            self._put("next_step", 4)
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
            "Retrieved from form asr_text of length %s", len(asr_text))
        if asr_text:
            self._put("asr_text", asr_text)

        if not login_voice:
            self.logger.warning(
                "Authentication flow, voice is NOT present in request so return false and keep step")
            self._put("retry_error", True)
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
            endpoint=self.endpoint, route=for_method)

        url = URI(whispeak_service_url)

        self.logger.debug("URL Token %s", url)
        get_connection = HttpGet(url)
        bearer = "Bearer {key}".format(key=self.api_key)
        self.logger.debug("Bearer Token: %s", bearer)
        get_connection.setHeader("Authorization", bearer)

        try:
            http_get_response = HttpClientBuilder.create().build().execute(get_connection)
            http_response_entity = http_get_response.getEntity()
            http_response_content = http_response_entity.getContent()
            if http_get_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                self.logger.error("Whispeak Obtain Access Token - SERVER resp NOT OK code %s",
                                  http_get_response.getStatusLine().getStatusCode())
                http_get_response.close()
                return None

            data = json.loads(IOUtils.toString(http_response_content, "UTF-8"))
            http_get_response.close()
            self.logger.debug("Access Token and Text: %s", data)
            return data

        except Exception as e:
            self.logger.error(
                "Whispeak Obtain Access Token Exception %s", str(e))
            return None
        finally:
            get_connection.releaseConnection()

    def _delete_signature(self, whispeak_signature_id):

        whispeak_service_url = "{endpoint}/signatures/{whispeak_signature_id}".format(
            endpoint=self.endpoint, whispeak_signature_id=whispeak_signature_id)

        url = URI(whispeak_service_url)
        self.logger.debug("URL Delete %s", url)
        get_connection = HttpDelete(url)
        bearer = "Bearer {key}".format(key=self.api_key)
        self.logger.debug("Bearer Delete, bearer %s", bearer)
        get_connection.setHeader("Authorization", bearer)

        try:
            http_delete_response = HttpClientBuilder.create().build().execute(get_connection)
            if http_delete_response.getStatusLine().getStatusCode() != HttpStatus.SC_OK:
                self.logger.error("Whispeak Delete signature - SERVER resp NOT OK code %s",
                                  http_delete_response.getStatusLine().getStatusCode())
                return False
            self.logger.info("Whispeak Delete signature code %s",
                             http_delete_response.getStatusLine().getStatusCode())
        except Exception as e:
            self.logger.error(
                "Whispeak Delete Signature Exception %s", str(e))
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
        self._put("token", data['token'])
        self._put("asr_text", data['text'])
        return True

    def _whispeak_voice(self, operation, login_voice, whispeak_signature_id=None):

        whispeak_service_url = "{endpoint}/{operation}".format(
            endpoint=self.endpoint, operation=operation)

        builder = URIBuilder(whispeak_service_url)
        url = builder.build()
        self.logger.debug("URL %s", url)
        http_service_request = HttpPost(url)

        try:
            token = self._get("token")
            self.logger.debug("JWT temp token %s", token)
            http_service_request.setHeader("Authorization", "Bearer " + token)
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
            http_service_response = HttpClientBuilder.create().build().execute(
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
                self._put("revocation_ui_link",
                          response_body['revocation']['revocation_ui_link'])
                self._put(
                    "revocation_pwd", response_body['revocation']['signature_secret_password'])
                return response_body["id"]
            if status_code == 404:
                self._remove_signature_from_user(whispeak_signature_id)
                return False
            self._put("retry_error", True)
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, self._whispeak_error_message(status_code))
            self.logger.warning(
                "Operation FAILED with code%s", http_service_response.getStatusLine())
            return False
        except Exception as e:
            if http_service_response:
                self.logger.info("Operation FAILED with code %s",
                                 http_service_response.getStatusLine())
            self.logger.error("Whispeak Auth Exception %s", str(e))
            return False
        finally:
            if http_service_response:
                http_service_response.close()
            http_service_request.releaseConnection()

    def _remove_signature_from_user(self, whispeak_signature_id):
        user = CdiUtil.bean(UserService).getUserByAttribute(
            'whispeakSignatureId', whispeak_signature_id)
        user.setAttribute('whispeakSignatureId', '')
        user.setAttribute('whispeakRevocationUiLink', '')
        user.setAttribute('whispeakRevocationPwd', '')
        CdiUtil.bean(UserService).updateUser(user)
        self.logger.info(
            "Removed non existent user signature from Gluu %s to force enrollment again (probably speaker secret was removed)", whispeak_signature_id)
        self._put("next_step", "1")
        self._set_message_error(
            FacesMessage.SEVERITY_ERROR, "whispeak.login.signatureDoesNotExist")

    def _whispeak_error_message(self, code):
        error_messages = {
            400: "whispeak.apiError.badRequest",
            401: "whispeak.apiError.unauthorized",
            403: "whispeak.apiError.invalidCredential",
            404: "whispeak.apiError.signatureNotFound",
            415: "whispeak.apiError.unsupportedAudioFile",
            419: "whispeak.apiError.voiceMismatch",
            420: "whispeak.apiError.audioConstraintsFailed",
            430: "whispeak.apiError.invalidEnrollSignature"
        }
        return error_messages[code]

    ################################################################################
    # Passport functions
    ################################################################################

    def _prepare_passport(self):
        if not self._get("external_providers"):
            self.registered_providers = self._parse_provider_configs()
            self._put("external_providers", json.dumps(
                self.registered_providers))

    def _get_passport_redirect_url(self, provider):

        self.logger.debug("Prepare passport for Provider %s", provider)

        # provider is assumed to exist in self.registered_providers
        url = None

        token_endpoint = "https://%s/passport/token" % CdiUtil.bean(
            FacesContext).getExternalContext().getRequest().getServerName()

        self.logger.debug(
            "Obtaining token from passport at %s", token_endpoint)
        resultResponse = CdiUtil.bean(HttpService).executeGet(
            HttpClientBuilder.create().build(), token_endpoint, Collections.singletonMap("Accept", "text/json"))
        http_response = resultResponse.getHttpResponse()
        message_bytes = CdiUtil.bean(
            HttpService).getResponseContent(http_response)

        response = CdiUtil.bean(
            HttpService).convertEntityToString(message_bytes)
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
            self._put("selected_provider", provider)
            return True

        return False

    def _redirect_oidc(self):
        provider = self._get("selected_provider")
        if not provider:
            return False
        url = self._get_passport_redirect_url(provider)
        if not url:
            return False
        self.logger.info("Redirecting user to OIDC url: %s", url)
        self._put("selected_provider", None)
        CdiUtil.bean(FacesService).redirectToExternalURL(url)
        return True

    def _is_oidc_authenticated(self, jwt_param):

        # Parse JWT and validate
        self.logger.info("Checking user OIDC token")
        jwt = Jwt.parse(jwt_param)
        (user_profile) = self._get_user_profile(jwt)
        if user_profile is None:
            return False

        auth_step1_username = self._get("username")

        if not self._validate_username_oidc(auth_step1_username, user_profile):
            self.logger.error(
                "FAIL not possible to verify username returns false")
            self._set_message_error(
                FacesMessage.SEVERITY_ERROR, "login.authOidcMismatch")
            return False
        return user_profile

    def _validate_username_oidc(self, auth_step1_username, user_profile):

        oidc_username = user_profile["mail"][0]

        if self.check_only_username:
            auth_step1_username = auth_step1_username.split("@")[0]
            oidc_username = oidc_username.split("@")[0]

        self.logger.debug(
            "Validate username matches with third-party username")

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
        config = LdapOxPassportConfiguration()
        config = CdiUtil.bean(PersistenceEntryManager).find(
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

    def _create_user(self, user_email, signature_id=None, profile=None, user_password=None):
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

        new_user = CdiUtil.bean(UserService).addUser(new_user, True)

        return new_user

    def _update_user(self, user, profile):
        self._fill_user(user, profile)
        CdiUtil.bean(UserService).updateUser(user)

    def _fill_user(self, user, profile):
        if profile:
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

    def _set_message_error(self, severity, msg, clear=True):
        if clear:
            self._new_messages()
        error_message = String.format("#{msgs['%s']}", msg)
        self.logger.debug("Error message to be returned %s", error_message)
        CdiUtil.bean(FacesMessages).add(severity, error_message)

    def _new_messages(self):
        CdiUtil.bean(FacesMessages).clear()

    def _response_content_entity(self, http_service_response):
        input_stream = http_service_response.getEntity().getContent()
        reader = BufferedReader(InputStreamReader(input_stream, "UTF-8"), 8)
        string_buffer = ""
        line = reader.readLine()
        while line is not None:
            string_buffer = string_buffer + line.encode('utf-8') + "\n"
            line = reader.readLine()
        return json.loads(string_buffer)
