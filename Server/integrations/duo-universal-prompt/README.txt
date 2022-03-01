# Duo Security using Universal Prompt
## Overview
[Duo Security](https://duosecurity.com) is a SaaS authentication provider. This document will explain how to use Gluu's [Duo interception script](https://github.com/GluuFederation/oxAuth/blob/master/Server/integrations/duo-universal-prompt/DuoUniversalPromptExternalAuthenticator.py) to configure the Gluu Server for a two-step authentication process with username and password as the first step, and Duo as the second step. The script invokes the Universal Prompt which is a redesign of Duo’s traditional authentication prompt. 

In order to use this authentication mechanism your organization will need a Duo account and users will need to download the Duo mobile app. 

## Prerequisites
- A Gluu Server ([installation instructions](../installation-guide/index.md));
- [Duo interception script](https://github.com/GluuFederation/oxAuth/blob/master/Server/integrations/duo-universal-prompt/DuoUniversalPromptExternalAuthenticator.py) (included in the default Gluu Server distribution);
- An account with [Duo Security](https://duo.com/).   


## Configure Duo AccountS

1. [Sign up](https://duo.com/) for a Duo account.

2. Log in to the Duo Admin Panel and navigate to Applications.

3. Click Protect an Application and locate Web SDK in the applications list. Click Protect this Application to get your client ID, secret key, and API hostname.

For additional info for the steps refer to Duo's Web SDK 4, check [this article](https://duo.com/docs/duoweb-v4). 

## Add the duo-universal Dependency to your oxAuth

Note: The dependencies have to be added seperately as mentioned in the steps below. Using a fat jar (duo-universal-sdk-1.0.3-with-dependencies.jar leads to conflicts.)
	1. Copy these jar files to the following oxAuth folder inside the Gluu Server chroot: /opt/gluu/jetty/oxauth/custom/libs
       Dependency jars : 
		[duo-universal-sdk-1.0.3.jar](https://repo1.maven.org/maven2/com/duosecurity/duo-universal-sdk/1.0.3/duo-universal-sdk-1.0.3.jar) ,
		[converter-jackson-2.1.0.jar](https://repo1.maven.org/maven2/com/squareup/retrofit2/converter-jackson/2.1.0/converter-jackson-2.1.0.jar) ,
                [java-jwt-3.3.0.jar] (https://repo1.maven.org/maven2/com/auth0/java-jwt/3.3.0/java-jwt-3.3.0.jar),
		[logging-interceptor-3.3.1.jar](https://repo1.maven.org/maven2/com/squareup/okhttp3/logging-interceptor/3.3.1/logging-interceptor-3.3.1.jar),
		[lombok-1.18.16.jar](https://repo1.maven.org/maven2/org/projectlombok/lombok/1.18.16/lombok-1.18.16.jar),
		[retrofit-2.5.0.jar](https://repo1.maven.org/maven2/com/squareup/retrofit2/retrofit/2.5.0/retrofit-2.5.0.jar),
		[okio-2.9.0.jar](https://repo1.maven.org/maven2/com/squareup/okio/okio/2.9.0/okio-2.9.0.jar),
		[okhttp-3.12.0.jar](https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/3.12.0/okhttp-3.12.0.jar),
		[kotlin-stdlib-1.4.21.jar](https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.4.21/kotlin-stdlib-1.4.21.jar)	   

	1. Edit /opt/gluu/jetty/oxauth/webapps/oxauth.xml and add the following line:
<Set name="extraClasspath">./custom/libs/duo-universal-sdk-1.0.3.jar,./custom/libs/converter-jackson-2.1.0.jar,./custom/libs/java-jwt-3.3.0.jar,./custom/libs/logging-interceptor-3.3.1.jar,./custom/libs/lombok-1.18.16.jar,./custom/libs/retrofit-2.5.0.jar,./custom/libs/okio-2.9.0.jar,./custom/libs/okhttp-3.12.0.jar,./custom/libs/kotlin-stdlib-1.4.21.jar</Set>


	1. Restart the oxauth service


## Configure oxTrust 

Follow the steps below to configure the Duo module in the oxTrust Admin GUI.

1. Navigate to `Configuration` > `Person Authentication Scripts`.
   Add a custom script for the 2 factor authentication using DUO credentials and name it duo2 (specifically because this is version 2 ).  


1. Add the following Custom Property ( key/value pairs ) 


|	Property	|Status		|	Description	|	Example		|
|-----------------------|---------------|-----------------------|-----------------------|
|api_hostname		|Mandatory     |URL of the Duo API Server|api-random.duosecurity.com|
|client_id		|Mandatory    |Value from the Duo application using Web SDK 4 that was registered using DUO Admin console|DI3ICTTJKLL8PPPNGH7YI|
|client_secret	|Mandatory|Value from the Duo application using Web SDK 4 that was registered using DUO Admin console|eEbJdi3hg42zxyFYbHArU5RuioPP|   

1. Enable the script by ticking the check box    
![enable](../img/admin-guide/enable.png)

Now Duo is an available authentication mechanism for your Gluu Server. This means that, using OpenID Connect `acr_values`, applications can now request Duo authentication for users. 

!!! Note 
    To make sure Duo has been enabled successfully, you can check your Gluu Server's OpenID Connect configuration by navigating to the following URL: `https://<hostname>/.well-known/openid-configuration`. Find `"acr_values_supported":` and you should see `"duo2"`. 

## Make Duo the Default Authentication Mechanism

Now applications can request Duo authentication, but what if you want to make Duo your default authentication mechanism? You can follow these instructions: 

1. Navigate to `Configuration` > `Manage Authentication`. 
2. Select the `Default Authentication Method` tab. 
3. In the Default Authentication Method window you will see two options: `Default acr` and `oxTrust acr`. 

    - The `oxTrust acr` field controls the authentication mechanism that is presented to access the oxTrust dashboard GUI (the application you are in).    
    - The `Default acr` field controls the default authentication mechanism that is presented to users from all applications that leverage your Gluu Server for authentication.    

You can change one or both fields to Duo authentication as you see fit. If you want Duo to be the default authentication mechanism for access to oxTrust and all other applications that leverage your Gluu Server, change both fields to Duo.  
 
!!! Note 
    Currently, the DUO Universal Prompt has not yet been released. However, DUO has enabled customers to be application ready so that the switch to the newer User Interface can be seamless.  

## Upgrading to the DUO Universal Prompt from the older user interface for enrolling DUO credentials

### In DUO Admin Console:
1. Register a new Duo's Web SDK 4 application, check [this article](https://duo.com/docs/duoweb-v4).  
1. Save the client id and secret

### In oxTrust :
1. Update the original duo script to reflect the latest contents.
1. Add script properties as mentioned in the above steps. The client ID and client secret can be obtained from the Web SDK 4 application of the DUO admin console.

### Add the duo-universal Dependency to your oxAuth
Follow the exact steps mentioned previously in the document

