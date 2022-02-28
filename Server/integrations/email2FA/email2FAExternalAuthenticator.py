

from org.gluu.oxauth.service import AuthenticationService
from org.gluu.oxauth.service import UserService
from org.gluu.oxauth.auth import Authenticator
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service.common import ConfigurationService
from org.gluu.oxauth.service.common import EncryptionService
from org.gluu.jsf2.message import FacesMessages
from javax.faces.application import FacesMessage
from org.gluu.persist.exception import AuthenticationException
from datetime import datetime, timedelta
from java.util import GregorianCalendar, TimeZone
from java.io import File
from java.io import FileInputStream
from java.util import Enumeration, Properties

#dealing with smtp server
from java.security import Security
from javax.mail.internet import MimeMessage, InternetAddress
from javax.mail import Session, Message, Transport

from java.util import Arrays
import random
import string
import re
import urllib
import java
try:
    import json
except ImportError:
    import simplejson as json

class EmailValidator():
    regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'

    def check(self, email):

        if(re.search(self.regex,email)):
            print "EmailOTP.  - %s is a valid email format" % email
            return True
        else:
            print "EmailOTP.  - %s is an invalid email format" % email
            return False

class Token:
    #class that deals with string token

    def generateToken(self,lent):
        rand1="1234567890123456789123456789"
        rand2="9876543210123456789123456789"
        first = int(rand1[:int(lent)])
        first1 = int(rand2[:int(lent)])
        token = random.randint(first, first1)
        return token


class PersonAuthentication(PersonAuthenticationType):


    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):

        print "EmailOTP.  - Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "EmailOTP.  - Destroyed successfully"
        return True

    def getApiVersion(self):
        return 11

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True
    def getAuthenticationMethodClaims(self, configurationAttributes):
        return None

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):

        print "Email 2FA - Authenticate for step %s" % ( step)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()
        user_password = credentials.getPassword()
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        subject = "Gluu Authentication Token"
        session_attributes = identity.getSessionId().getSessionAttributes()
        multipleEmails = session_attributes.get("emailIds")

        if step == 1:
            try:
                 # Check if user authenticated already in another custom script
                user2 = authenticationService.getAuthenticatedUser()
                if user2 == None:
                    credentials = identity.getCredentials()
                    user_name = credentials.getUsername()
                    user_password = credentials.getPassword()

                    logged_in = False
                    if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                        userService = CdiUtil.bean(UserService)
                        logged_in = authenticationService.authenticate(user_name, user_password)
                        if logged_in is True:
                            user2 = authenticationService.getAuthenticatedUser()
                            emailIds = user2.getAttribute("oxEmailAlternate")
                            if StringHelper.isNotEmptyString(emailIds):
                                data = json.loads(emailIds)
                                if len(data['email-ids']) > 1:
                                    commaSeperatedEmailString = []
                                    for email in data['email-ids']:
                                        reciever_id = email['email']
                                        commaSeperatedEmailString.append(reciever_id)
                                    # setting this in session is used to determine if this is a 2 or 3 step flow
                                    identity.setWorkingParameter("emailIds", ",".join(commaSeperatedEmailString))

                    return logged_in
            except AuthenticationException as err:
                print err
                return False
        else:
            #Means the selection email page was used
            user2 = authenticationService.getAuthenticatedUser()
            emailIds = user2.getAttribute("oxEmailAlternate")
            if emailIds != None:
                multipleEmails = []
                token = identity.getWorkingParameter("token")

                if StringHelper.isNotEmptyString(emailIds):
                    data = json.loads(emailIds)

                    # step2 and multiple email ids present, then user has been presented a choice of email which is fetched in OtpEmailLoginForm:indexOfEmail, send email
                    if step == 2 and len(data['email-ids']) > 1 :

                        for email in data['email-ids']:
                            reciever_id = email['email']
                            multipleEmails.append(reciever_id)


                        idx = ServerUtil.getFirstValue(requestParameters, "OtpEmailLoginForm:indexOfEmail")
                        if idx != None and token != None:
                            sendToEmail = multipleEmails[int(idx)]
                            print "EmailOtp. Sending email to : %s " % sendToEmail

                            body = "Here is your token: %s" % token
                            sender = EmailSender()
                            sender.sendEmail( sendToEmail, subject, body)
                            return True
                        else:
                            print "EmailOTP. Something wrong with index or token"
                            return False
                    # token verificaation - step 3 incase of email selection , else step 2
                    else:
                        input_token = ServerUtil.getFirstValue(requestParameters, "OtpEmailLoginForm:passcode")
                        print "input token %s" % input_token
                        print "EmailOTP.  - Token input by user is %s" % input_token

                        token = str(identity.getWorkingParameter("token"))
                        min11 = int(identity.getWorkingParameter("sentmin"))
                        nww = datetime.now()
                        te = str(nww)
                        listew = te.split(':')
                        curtime = int(listew[1])

                        token_lifetime = int(configurationAttributes.get("token_lifetime").getValue2())
                        if ((min11<= 60) and (min11>= 50)):
                            if ((curtime>=50) and (curtime<=60)):
                                timediff1 =  curtime -  min11
                                if timediff1>token_lifetime:
                                    #print "OTP Expired"
                                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "OTP Expired")
                                    return False
                            elif ((curtime>=0) or (curtime<=10)):
                                timediff1 = 60 - min11
                                timediff1 =  timediff1 + curtime
                                if timediff1>token_lifetime:
                                    #print "OTP Expired"
                                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "OTP Expired")
                                    return False

                        if ((min11>=0) and (min11<=60) and (curtime>=0) and (curtime<=60)):
                            timediff2 = curtime - min11
                            if timediff2>token_lifetime:
                                #print "OTP Expired"
                                facesMessages.add(FacesMessage.SEVERITY_ERROR, "OTP Expired")
                                return False
                        # compares token sent and token entered by user
                        print "Token from session: %s " % token
                        if input_token == token:
                            print "Email 2FA - token entered correctly"
                            identity.setWorkingParameter("token_valid", True)

                            return True

                        else:
                            facesMessages = CdiUtil.bean(FacesMessages)
                            facesMessages.setKeepMessages()
                            facesMessages.clear()
                            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Wrong code entered")
                            print "EmailOTP. Wrong code entered"
                            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "EmailOTP.  - Preparing for step %s" % step
        authenticationService = CdiUtil.bean(AuthenticationService)

        user2 = authenticationService.getAuthenticatedUser()


        if step == 2 and user2 is not None:
            uid = user2.getAttribute("uid")
            identity = CdiUtil.bean(Identity)
            lent = configurationAttributes.get("token_length").getValue2()
            new_token = Token()
            token = new_token.generateToken(lent)
            subject = "Gluu Authentication Token"
            body = "Here is your token: %s" % token

            sender = EmailSender()
            emailIds = user2.getAttribute("oxEmailAlternate")

            print "emailIds : %s" % emailIds
            data = json.loads(emailIds)

            #Attempt to send message now if user has only one email id
            if len(data['email-ids']) == 1:
                email = data['email-ids'][0]
                print "EmailOTP.  email to - %s" % email['email']
                sender.sendEmail( email['email'], subject, body)

            else:
                commaSeperatedEmailString = []
                for email in data['email-ids']:
                    reciever_id = email['email']
                    print "EmailOTP. Email to - %s" % reciever_id
                    #sender.sendEmail( reciever_id, subject, body)
                    commaSeperatedEmailString.append(self.getMaskedEmail(reciever_id))
                identity.setWorkingParameter("emailIds", ",".join(commaSeperatedEmailString))

            otptime1 = datetime.now()
            tess = str(otptime1)
            listee = tess.split(':')

            identity.setWorkingParameter("sentmin", listee[1])
            identity.setWorkingParameter("token", token)

            return True

        return True

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("token","emailIds","token_valid","sentmin")


    def getCountAuthenticationSteps(self, configurationAttributes):

        print "EmailOTP. getCountAuthenticationSteps called"

        if CdiUtil.bean(Identity).getWorkingParameter("emailIds") == None:
            print "EmailOTP. getCountAuthenticationSteps called - 2 steps"
            return 2
        else:
            print "EmailOTP. getCountAuthenticationSteps called 3 steps"
            return 3


    def getPageForStep(self, configurationAttributes, step):
        print "EmailOTP. getPageForStep called %s" % step

        defPage = "/casa/otp_email.xhtml"
        if step == 2:
            if CdiUtil.bean(Identity).getWorkingParameter("emailIds") == None:
                print "emailIds not set, returning otp_email page"
                return defPage
            else:
                return "/casa/otp_email_prompt.xhtml"
        elif step == 3:
            return defPage
        return ""



    def getNextStep(self, configurationAttributes, requestParameters, step):
        return -1

    def logout(self, configurationAttributes, requestParameters):
        return True

    def hasEnrollments(self, configurationAttributes, user):
        values = user.getAttributeValues("oxEmailAlternate")
        if values != None:
            return True
        else:
            return False


    def getMaskedEmail (self, emailid):
        regex = r"(?<=.)[^@\n](?=[^@\n]*?@)|(?:(?<=@.)|(?!^)\G(?=[^@\n]*$)).(?=.*\.)"
        subst = "*"
        result = re.sub(regex, subst, emailid, 0, re.MULTILINE)
        if result:
            print (result)
        return result

class EmailSender():
    #class that sends e-mail through smtp

    def getSmtpConfig(self):

        smtp_config = None
        smtpconfig = CdiUtil.bean(ConfigurationService).getConfiguration().getSmtpConfiguration()

        if smtpconfig is None:
            print "Sign Email - SMTP CONFIG DOESN'T EXIST - Please configure"

        else:
            encryptionService = CdiUtil.bean(EncryptionService)
            smtp_config = {
                'host' : smtpconfig.getHost(),
                'port' : smtpconfig.getPort(),
                'user' : smtpconfig.getUserName(),
                'from' : smtpconfig.getFromEmailAddress(),
                'pwd_decrypted' : encryptionService.decrypt(smtpconfig.getPassword()),
                'req_ssl' : smtpconfig.isRequiresSsl(),
                'requires_authentication' : smtpconfig.isRequiresAuthentication(),
                'server_trust' : smtpconfig.isServerTrust()
            }

        return smtp_config



    def sendEmail(self,  useremail, subject, messageText):
        # server connection
        smtpconfig = self.getSmtpConfig()

        properties = Properties()
        properties.setProperty("mail.smtp.host", smtpconfig['host'])
        properties.setProperty("mail.smtp.port", str(smtpconfig['port']))
        properties.setProperty("mail.smtp.starttls.enable", "true")
        session = Session.getDefaultInstance(properties)

        message = MimeMessage(session)
        message.setFrom(InternetAddress(smtpconfig['from']))
        message.addRecipient(Message.RecipientType.TO,InternetAddress(useremail))
        message.setSubject(subject)
        #message.setText(messageText)
        message.setContent(messageText, "text/html")

        transport = session.getTransport("smtp")
        transport.connect(properties.get("mail.smtp.host"),int(properties.get("mail.smtp.port")), smtpconfig['user'], smtpconfig['pwd_decrypted'])
        transport.sendMessage(message,message.getRecipients(Message.RecipientType.TO))


        transport.close()
