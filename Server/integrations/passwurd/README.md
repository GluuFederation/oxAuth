# Passwurd keystroke API Authentication

## Overview

This interception script allows administrators to deploy a keystroke authentication flow in Gluu Server. 

In short the flow works as follows:

### Usecase - Password not yet enrolled:
- A form is shown where a username is prompted
- The server recognizes that the user has not yet enrolled his password and therefore presents the user with the 2FA authentication page. Depending on the available credentials and configuration, the user may choose to present a different alternative credential.
- Once the second factor is presented and validated successfully, the user's browser is redirected to the target application


### Usecase - After password enrollment:
- A form is shown where a username is prompted
- Incase, a user has configured / enrolled a password, his password page is presented and the keystrokes of the entered password are validated against the Keystroke API.
- Incase, the Keystroke API fails to recognize the user's keystrokes, a query is issued in the underlying database for credentials that potentially may be employed as a second factor
- A form is shown where the user must present a certain credential in order to gain access. Depending on the available credentials and configuration, the user may choose to present a different alternative credential
- Once the second factor is presented and validated successfully, the user's browser is redirected to the target application


### Additionally, there are some features worth noting:

- Configurable [authentication mechanisms for second factor](#authentication-mechanisms-for-second-factor)

## Flow setup

### Requirements

- Ensure you have a running instance of Gluu Server 4.4
- While not a requisite, usage of [Gluu Casa](https://casa.gluu.org) is highly recommended as part of your 2FA solution. Among others this app helps users to enroll their authentication credentials which is a key aspect for 2FA authentication to take place. 

### Enable 2FA-related scripts

1. Log in to oxTrust with admin credentials
2. Visit `Configuration` > `Person Authentication Scripts`, click on `fido2` and ensure the script is flagged as enabled 
3. If you want to support [Super Gluu](supergluu.md) as second factor too, enable the `super_gluu` script. Support for biometric authentication is available as well, for this purpose follow [these instructions](https://www.gluu.org/docs/gluu-server/authn-guide/BioID/) 

### Add the Passwurd script

1. Log in to oxTrust with admin credentials
2. Visit `Configuration` > `Person Authentication Scripts`. At the bottom click on `Add custom script configuration` and fill values as follows:
   - For `name` use a meaningful identifier, like `passwurd`
   - In the `script` field use the contents of this [file](https://github.com/GluuFederation/oxAuth/raw/version_4.4.0/Server/integrations/passwurd/PasswurdAuthentication.py)
   - Tick the `enabled` checkbox
   - For the rest of fields, you can accept the defaults
3. Click on `Add new property`. On the left type `snd_step_methods`, on the right use `fido2,super_gluu` or whatever suits your needs best. See [Authentication mechanisms for second factor](#authentication-mechanisms-for-second-factor) for more
4. Configure the following properties

|Name|Description|Sample value|
|-|-|-|
|`snd_step_methods`|Optional. It contains a comma-separated list of identifiers of authentication methods that will be part of the second step of the flow. Note order is relevant: a method appearing first is preferred (prompted) over one appearing further in the list|otp, twilio_sms, super_gluu|
|`AS_ENDPOINT`|Jans server URL|`https://<your-host-name>`|
|`PORTAL_JWKS`|JWKS used for signing SSA|`https://<portal-host-name>/jwks`|
|`PASSWURD_KEY_A_PASSWORD`|PASSWURD_KEY_A_PASSWORD|`zxcvb`|
|`PASSWURD_KEY_A_KEYSTORE`|PASSWURD_KEY_A_KEYSTORE|`/etc/certs/passwurdAKeystore.pcks12`|
|`AS_CLIENT_ID`|THis should be populated after client creation|`abcdefghij`|
|`AS_CLIENT_SECRET`|This should be populated after client creation in the initialization|`abcdefgh`|
|`AS_REDIRECT_URI`|Jans server's redirect URI|`https://sample-hello-gateway-15pnmz0m.uc.gateway.dev`|
|`AS_SSA`|SSA for client creation on Jans server. JWT signed using the JWKS URI|`eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImdsdXUtc2Nhbi1hcGkifQ.eyJpc3MiOiJodHRwczovL3BvcnRhbC5nbHV1Lm9yZyIsImlhdCI6IjE2NTUzMTkyNjgiLCJqdGkiOiJmN2I1OTkxYy00YzE4LTRjODEtYTY2NC1lNmY4NjcwZjVkNTEiLCJzb2Z0d2FyZV9pZCI6ImdsdXUtc2Nhbi1hcGkiLCJvcmdfaWQiOjEsInNvZnR3YXJlX3JvbGVzIjpbInBhc3N3dXJkIl0sImp3a3NfdXJpIjoiaHR0cHM6Ly9jbG91ZC1kZXYuZ2x1dS5jbG91ZC9wb3J0YWwvandrcyIsIm9yZ19zdGF0dXMiOiJhY3RpdmUiLCJhcHBsaWNhdGlvbl90eXBlIjoid2ViIiwiZ3JhbnRfdHlwZXMiOiJjbGllbnRfY3JlZGVudGlhbHMiLCJyZXNwb25zZV90eXBlcyI6InRva2VuIn0.CfFL4uI-K6jHkN7DB7YofjDgjH_9a5nWTVrC9eILBH72JTuLmbX_JfNYDXkTJlzCGdJGtRilCJuCPa1WCmTNSKu16d8UlpMoRfgFlND01pPOrFDtXitSktDUTMV7jNdhIt7lmRtMF0XjPFi13pf2ur1ZgDVodkokvmV4kebRfjv6RXQ3wCbP57L8eFL9C95WtGUJLefpi0i-88RFxv36XALMYhyq7OYLtCjv62Fh9j8jpcEmWCmQV8FKVNhvqrVyf3GGqoBCyRkQDJOGRCbL-5BAAylzlglvXkAZCM8lP5GovnmCPc_WQY2TK8AsWTMYIs_wWJJ9LAoXPk2CwtC6JKo9gxWsyDJCXnc4a_IkC_rOiWutVqQ_LmaAbjqHdL1KX6eVfmVDLXrIoS6ic4f3PbqlPPk7CIM2c9ydEV4lVi5rFGxlO_yBwS3ptJzMFW0i6rpxZMpHVe9I2F7leZqZhzf0D6ayLJBwpifQwgHps8CX5fFawWVESZgU2kgEq4MR_24ghqk24VC1scolWZdegYZClvZtFOkqcX9T_-9lpKswrGfr6lMEtzuNwfhteccZG6tihC6M-7fXnqMDjpA_ct43FjKFqV79OelLrEtjiZfx8-etfak7K2u-ebm8S_aO3g17dO2BUaQsulV_4uxeH1t3COGaJsyMKNagKkiJg6g`|
|`PASSWURD_API_URL`|This is used to query keystroke endpoint|`https://cloud-dev.gluu.cloud/scan`|

5. If `super_gluu` was listed in the previous step, click on `Add new property`. On the left type `supergluu_app_id`, on the right use `https://<your-gluu-host-name>/casa`. This is the URL (aka application ID) that Super Gluu enrollments are already (or will be) associated to.
6. Scroll down and click on the `Update` button at the bottom of the page


### Transfer script assets to your server

Extract [this file](https://github.com/GluuFederation/oxAuth/raw/version_4.4.0/Server/integrations/passwurd/bundle.zip) to the root (ie. `/`) of your Gluu server. In a standard CE installation this means extraction should take place under `/opt/gluu-server`.

The zip file contains UI pages (forms), associated javascript and CSS files, as well as miscellaneous python code required for the flow to run properly. When extracting use the `root` user. 


## Authentication mechanisms for second factor

In a 2fa authentication scenario you may want to offer a trusted/restricted set of authentication methods for use in the second step. A popular choice for this is FIDO. The passwordless flow offered by Gluu also supports [Super Gluu](supergluu.md) as well as Biometric authentication by [BioID](https://www.bioid.com/).

Please note the `snd_step_methods` custom property of the passwurd interception script in oxTrust. It contains a comma-separated list of identifiers of authentication methods that will be part of the second step of the flow. Note order is relevant: a method appearing first is preferred (prompted) over one appearing further in the list. 

## Test 

Create one or more users for testing. These users should have already enrolled credentials belonging to one or more of the methods listed in `snd_step_methods` property of the script. For this purpose [Casa](https://casa.gluu.org) is a natural choice.

In a testing RP (eg. web application) issue authentication requests such that the `acr_values` parameter is set to the name of the passwordless script. 

!!! Note
    Users without credentials belonging to any of the methods in `snd_step_methods` won't get past the first step of the flow.
