# Stytch one time passcodes over SMS

## Overview 
Integrate Stytch one-time passcodes as your multi-factor authentication solution.
This document explains how to configure the Gluu Server for two-step, two-factor authentication (2FA) with username / password as the first step, and an OTP sent via text message as the second step. 

    
## Prerequisites 

- A Gluu Server (installation instructions [here](../installation-guide/index.md));    
- The [Stytch SMS OTP script](https://github.com/GluuFederation/oxAuth/blob/master/Server/integrations/stytch/stytchExternalAuthenticator.py)    

- A mobile device and phone number that can receive SMS text messages


## Properties

The custom script has the following properties:    
|	Property	        |	Description		                                      |	Example	|
|-----------------------|-------------------------------|---------------|
|SMS_ENDPOINT		    |https://stytch.com/docs/api/send-otp-by-sms              |`https://test.stytch.com/v1/otps/sms/send`|
|AUTH_ENDPOINT 		    |https://stytch.com/docs/api/authenticate-otp             |`https://test.stytch.com/v1/otps/authenticate`|
|ENROLL_ENDPOINT	    |https://stytch.com/docs/api/log-in-or-create-user-by-sms |`https://test.stytch.com/v1/otps/sms/login_or_create`|
|PROJECT_ID 		    |Project id provided by Stytch.                           |`project-test-dd1403b3-dd92-33c6-91dd-ddcde970a61e`|
|SECRET		            |secret provided by Stytch.                               |`secret-test-dd1403b3-dd92-33c6-91dd-ddcde970a61e`|


## Enable stytch acr

### Add the custom script

1.  Log into oxTrust with admin credentials

1.  Visit `Configuration` > `Person Authentication Scripts`. At the bottom click on `Add custom script configuration` and fill values as follows:

    - For `name` use a meaningful identifier, like `stytch`
    
    - In the `script` field use the contents of this [file](https://github.com/GluuFederation/oxAuth/raw/version_4.5.1/Server/integrations/stytch/stytchExternalAuthenticator.py)
    
    - Tick the `enabled` checkbox
    
    - For the rest of fields, you can accept the defaults
    
1.  Click on `Add new property`. On the left enter `SMS_ENDPOINT` on the right copy the corresponding value you will find in your stytch account https://stytch.com/docs/api/send-otp-by-sms 

1.  Repeat the process for `AUTH_ENDPOINT`, `ENROLL_ENDPOINT`, `PROJECT_ID` and `SECRET`

1.  Scroll down and click on the `Update` button at the bottom of the page
Now Stytch is an available authentication mechanism for your Gluu Server. This means that, using OpenID Connect `acr_values`, applications can now request OTP SMS authentication for users. 

!!! Note 
    To make sure Stytch has been enabled successfully, you can check your Gluu Server's OpenID Connect configuration by navigating to the following URL: `https://<hostname>/.well-known/openid-configuration`. Find `"acr_values_supported":` and you should see `"stytch"`. 

## Make Stytch the Default
If Stytch should be the default authentication mechanism, follow these instructions: 

1. Navigate to `Configuration` > `Manage Authentication`. 

1. Select the `Default Authentication Method` tab. 

1. In the Default Authentication Method window you will see two options: `Default acr` and `oxTrust acr`. 

 - `oxTrust acr` sets the authentication mechanism for accessing the oxTrust dashboard GUI (only managers should have acccess to oxTrust).    

 - `Default acr` sets the default authentication mechanism for accessing all applications that leverage your Gluu Server for authentication (unless otherwise specified).    

If Stytch should be the default authentication mechanism for all access, change both fields to stytch.  
    
## SMS OTP Login Pages

The Gluu Server includes one page for SMS OTP:

1. A **login** page that is displayed for all SMS OTP authentications. 
![sms](../img/user-authn/sms.png)

The designs are being rendered from the [SMS xhtml page](https://github.com/GluuFederation/oxAuth/blob/master/Server/src/main/webapp/auth/otp_sms/otp_sms.xhtml). To customize the look and feel of the pages, follow the [customization guide](../operation/custom-design.md).


## Using SMS OTP

### Phone Number Enrollment

The script assumes the user phone number is already stored in his corresponding LDAP entry (attribute `phoneNumberVerified`). You can change the attribute by altering the script directly (see authenticate routine).

### Subsequent Logins
All <!--subsequent--> authentications will trigger an SMS with an OTP to the registered phone number. Enter the OTP to pass authentication. 

### Credential Management
    
A user's registered phone number can be removed by a Gluu administrator either via the oxTrust UI in `Users` > `Manage People`, or in LDAP under the user entry. Once the phone number has been removed from the user's account, the user can re-enroll a new phone number following the [phone number enrollment](#phone-number-enrollment) instructions above. 

## Troubleshooting    
If problems are encountered, take a look at the logs, specifically `/opt/gluu/jetty/oxauth/logs/oxauth_script.log`. Inspect all messages related to Stytch. For instance, the following messages show an example of correct script initialization:

```
Stytch Initialization
Stytch Initialized successfully
```

Also make sure you are using the latest version of the script that can be found [here](https://github.com/GluuFederation/oxAuth/blob/master/Server/integrations/stytch/stytchExternalAuthenticator.py).

## Self-service account security

To offer end-users a portal where they can manage their own account security preferences, including two-factor authentication credentials like phone numbers for SMS OTP, check out our new app, [Gluu Casa](https://casa.gluu.org). 
