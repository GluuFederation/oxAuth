# Integrating Impossible travel feature by Deduce Insights in Passwordless Authentication flow.

## Overview
[Deduce](https://www.deduce.com/) is a cybersecurity company built on the premise of using data for good. We’ve repeatedly seen the impact of bad actors working together to cause damage and compromise customers and organizations alike. Deduce democratizes technologies and shifts the advantage back to the security community.

Deduce Identity Insights acts as a cyber security radar for validating good users and detecting fraudulent activity. The platform provides actionable data in relation to a user’s digital activity to enable smarter, more accurate security decisions. The Impossible travel alert which is a part of Insights service is raised when a user travels to a new location from a previous location within an unrealistic timeframe.

This document explains how to use the Gluu Server's included interception script that integrates this feature "Impossible travel " into the passwordless authentication flow.

This interception script allows administrators to deploy a passwordless authentication flow in Gluu Server. In short the flow works as follows:

- A form is shown where a username is prompted
- A query is issued in the underlying database for credentials that potentially may be employed as a second factor
- A form is shown where the user must present a certain credential in order to gain access. Depending on the available credentials and configuration, the user may choose to present a different alternative credential
- Once the second factor is presented and validated successfully, the user's browser is redirected to the target application

Additionally, there are some features worth noting:

- [login hint](#login-hint) support 
- [Account choice](#account-choice)
- Configurable [authentication mechanisms for second factor](#authentication-mechanisms-for-second-factor)

## Flow setup

### Requirements

- Ensure you have a running instance of Gluu Server 4.3
- While not a requisite, usage of [Gluu Casa](https://casa.gluu.org) is highly recommended as part of your 2FA solution. Among others this app helps users to enroll their authentication credentials which is a key aspect for passwordless authentication to take place. 

### Enable 2FA-related scripts

1. Log in to oxTrust with admin credentials
2. Visit `Configuration` > `Person Authentication Scripts`, click on `fido2` and ensure the script is flagged as enabled 
3. If you want to support [Super Gluu](https://super.gluu.org/home/) as second factor too, enable the `super_gluu` script. Support for biometric authentication is available as well, for this purpose follow [these instructions](https://www.gluu.org/docs/gluu-server/authn-guide/BioID/) 



### Add the passwordless script

1. Log in to oxTrust with admin credentials
2. Visit `Configuration` > `Person Authentication Scripts`. At the bottom click on `Add custom script configuration` and fill values as follows:
   - For `name` use a meaningful identifier, like `passwordless`
   - In the `script` field use the contents of this [file](https://github.com/GluuFederation/oxAuth/raw/version_4.2.3/Server/integrations/passwordless/PasswordlessAuthenticationWithDeduceImpossTravel.py)
   - Tick the `enabled` checkbox
   - For the rest of fields, you can accept the defaults
3. Click on `Add new property`. On the left type `snd_step_methods`, on the right use `fido2,super_gluu` or whatever suits your needs best. See [Authentication mechanisms for second factor](#authentication-mechanisms-for-second-factor) for more
4. The script has the following additional properties. Add the properties to the passwordless script.

|	Property	|	Description		|	Example	|
|-----------------------|-------------------------------|---------------|
|DEDUCE_ENDPOINT		|API endpoint provided by Deduce. |`https://api.deducesecurity.com/insights`|
|DEDUCE_API_KEY 		|API Key provided by Deduce. |`87d55ba11acd1a23ee6c054f3460154e`|
|DEDUCE_SITE		|site provided by Deduce. |`site name`|

5. If `super_gluu` was listed in the previous step, click on `Add new property`. On the left type `supergluu_app_id`, on the right use `https://<your-gluu-host-name>/casa`. This is the URL (aka application ID) that Super Gluu enrollments are already (or will be) associated to.
6. Scroll down and click on the `Update` button at the bottom of the page

**Notes:**

If you want to support Account Choice see the [corresponding section](#account-choice).

### Transfer script assets to your server

Extract [this file](https://github.com/GluuFederation/oxAuth/raw/version_4.2.3/Server/integrations/passwordless/bundle.zip) to the root (ie. `/`) of your Gluu server. In a standard CE installation this means extraction should take place under `/opt/gluu-server`.

The zip file contains UI pages (forms), associated javascript and CSS files, as well as miscellaneous python code required for the flow to run properly. When extracting use the `root` user. 

## Login Hint

When the authentication request that triggers the authentication contains the `login_hint` parameter (see http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest), this value is used to automatically populate the username input field in the initial form. 

## Account Choice

This feature shows a list of selectable usernames in order to save users some typing. The list is populated with usernames that were employed in recent successful login events in the given browser. In addition to the list, a "Use another account" link allows users to enter a different username if needed.

In order to configure this feature follow the steps below:

1. Log into oxTrust with admin credentials
2. Visit `Configuration` > `Person Authentication Scripts` and select the recently created entry for the passwordless script
3. Scroll down and click on `Add new property`
4. In the empty text field appearing on the left type `prevLoginsCookieSettings`
5. In the field on the right hand side paste the following:

```
{"enabled": true, "maxListSize": 4, "forgetEntriesAfterMinutes": 10080, "cookieName": "pwdlesscookie"}
```
6. Scroll down and click on the `Update` button

Note how the JSON content helps drive the behavior of account choice:

- `enabled` turns on and off this feature
- `maxListSize` helps keeping the list small. Only the most recent usernames will be shown up to the limit set by this property 
- `forgetEntriesAfterMinutes` is used to make individual list entries expire: if the last successful login attempt for a user took place long ago, it will not be part of the list anymore. The value provided in the example above corresponds to one week
- `cookieName`. Account choice is implemented by means of a browser cookie. This property is used to control its name.

Account choice also works in conjunction with [Login hint](#login-hint). If the given hint matches any of the remembered usernames, such username will appear first in the list, otherwise the hint will be shown once the "Use another account" link is clicked.

## Authentication mechanisms for second factor

In a passwordless scenario you may want to offer a trusted/restricted set of authentication methods for use in the second step. A popular choice for this is FIDO. The passwordless flow offered by Gluu also supports [Super Gluu](https://super.gluu.org/home/) as well as Biometric authentication by [BioID](https://www.bioid.com/).

Please note the `snd_step_methods` custom property of the passwordless interception script in oxTrust. It contains a comma-separated list of identifiers of authentication methods that will be part of the second step of the flow. Note order is relevant: a method appearing first is preferred (prompted) over one appearing further in the list. 

## Test 

Create one or more users for testing. These users should have already enrolled credentials belonging to one or more of the methods listed in `snd_step_methods` property of the script. For this purpose [Casa](https://casa.gluu.org) is a natural choice.

In a testing RP (eg. web application) issue authentication requests such that the `acr_values` parameter is set to the name of the passwordless script. Parameter `login_hint` can optionally be set.

!!! Note
    Users without credentials belonging to any of the methods in `snd_step_methods` won't get past the first step of the flow.
