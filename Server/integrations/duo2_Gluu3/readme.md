# Duo Universal Prompt configuration with Gluu 3.1.7

## Overview
[Duo Security](https://duosecurity.com) is a SaaS authentication provider. This document will explain how to configure Duo University Prompt with Gluu Server 3.1.7 for a two-step authentication process with username and password as the first step, and Duo as the second step. The script invokes the Universal Prompt which is a redesign of Duo’s traditional authentication prompt. 

In order to use this authentication mechanism your organization will need a Duo account and users will need to download the Duo mobile app. 

## Prerequisites
- A Gluu Server 3.1.7;
- Speical Duo2 script specific for Gluu Server 3.1.7 which is included above. 
- An account with [Duo Security](https://duo.com/).   


## Configure Duo AccountS

1. [Sign up](https://duo.com/) for a Duo account.

2. Log in to the Duo Admin Panel and navigate to Applications.

3. Click Protect an Application and locate Web SDK in the applications list. Click Protect this Application to get your client ID, secret key, and API hostname.

For additional info for the steps refer to Duo's Web SDK 4, check [this article](https://duo.com/docs/duoweb-v4). 

## Add the duo-universal Dependency to your oxAuth

1. Download Duo-Universal-SDK 1.0.3 (wget https://repo1.maven.org/maven2/com/duosecurity/duo-universal-sdk/1.0.3/duo-universal-sdk-1.0.3-jar-with-dependencies.jar)  and put it inside `/opt/gluu/jetty/oxauth/custom/libs`

1. Restart the oxauth service


## Configure oxTrust 

Follow the steps below to configure the Duo module in the oxTrust Admin GUI.

1. Navigate to `Configuration` > `Person Authentication Scripts`.
   Add a custom script for the 2 factor authentication using DUO credentials and name it duo2 (specifically because this is version 2 ).  


1. Add the following Custom Property ( key/value pairs ) 


|	Property	|Status		|	Description	|	Example		|
|-----------------------|---------------|-----------------------|-----------------------|
|api_hostname		|Mandatory     |URL of the Duo API Server|api-random.duosecurity.com|
|client_id		|Mandatory    |Value from the Duo application using Web SDK 4 that was registered using DUO Admin console|DIxxxxxxxxxxxXxxxI|
|client_secret	|Mandatory|Value from the Duo application using Web SDK 4 that was registered using DUO Admin console|eXXXXXXXXXXXXXXXP|   

1. Enable the script by ticking the check box    

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

