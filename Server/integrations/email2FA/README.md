# One-Time Password (OTP) Authentication over Email

## Overview
This document explains how to use the Gluu Server's included 
[Email_2fa interception script](https://raw.githubusercontent.com/GluuFederation/oxAuth/master/Server/integrations/email2FA/email2FAExternalAuthenticator.py) 
to implement a two-step, two-factor authentication (2FA) process with username / password as the first step, and an OTP recieved on email as the second step. 


## Prerequisites
- A Gluu Server ([installation instructions](../installation-guide/index.md))
- [Email_2fa interception script](https://raw.githubusercontent.com/GluuFederation/oxAuth/master/Server/integrations/email2FA/email2FAExternalAuthenticator.py) 
- SMTP configuration as per https://gluu.org/docs/gluu-server/4.3/admin-guide/oxtrust-ui/#smtp-server-configuration



## Properties
The OTP authentication script has the following properties: 

|	Property	|	Description		|	Example	|
|-----------------------|-------------------------------|---------------|
|token_length	|length (number of characters) of the OTP token| eg : 5 
|token_lifetime  |In minutes| 2
 
    
## Enable Email_2fa
Follow the steps below to enable Super Gluu authentication:

1. In oxTrust, navigate to `Configuration` > `Person Authentication Scripts`
1. Create a new script and give it a relevant name say email_2fa and In the script field use the contents of this [file](https://raw.githubusercontent.com/GluuFederation/oxAuth/master/Server/integrations/email2FA/email2FAExternalAuthenticator.py) 
1. Enable the script by checking the box 
1. Scroll to the bottom of the page and click `Update`

Now email_2fa is an available authentication mechanism for your Gluu Server. This means that, using OpenID Connect `acr_values`, applications can now request OTP authentication for users. 

## Make email_2fa the Default

If OTP should be the default authentication mechanism, follow these instructions: 

1. Navigate to `Configuration` > `Manage Authentication` 

1. Select the `Default Authentication Method` tab 

1. In the Default Authentication Method window you will see two options: `Default acr` and `oxTrust acr` 

 - `oxTrust acr` sets the authentication mechanism for accessing the oxTrust dashboard GUI (only managers should have acccess to oxTrust)    

 - `Default acr` sets the default authentication mechanism for accessing all applications that leverage your Gluu Server for authentication (unless otherwise specified)    

If email_2fa should be the default authentication mechanism for all access, change both fields to email_2fa.  

# Add 2FA login pages to oxauth 

1. ` mkdir -p /opt/gluu/jetty/oxauth/custom/pages/auth/email_auth `

1. ` cp entertoken.xhtml /opt/gluu/jetty/oxauth/custom/pages/auth/email_auth `
