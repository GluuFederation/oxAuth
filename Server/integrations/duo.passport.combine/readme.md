## DUO-Passport multiAuth set up [ Work in progress ... ] 

This script allow users to use Duo as two factor in a Passport enabled Gluu Server. 
There are two options in a Passport enabled Gluu Server: 
  - oxAuth login ( left side )
  - Passport login ( right side )

This script will ask for Duo when user will use oxAuth login. 

### Implementation Note

 - This implemented in one customer's 4.4.0.sp1
 - This script should work in 4.5 without downloading oxauth and Jetty modification ( below step number 1 and 2 ) 

### Configuration in Gluu CE 4.4.0

#### Download oxAuth 

Get `oxauth.war` from https://maven.gluu.org/maven/org/gluu/oxauth-server/4.4.0.sp1/oxauth-server-4.4.0.sp1.war

#### Jetty Compatible

By default old war files are for version 9. As result it apply small changes in war file to run it correctly under jetty 10.

 - Run `/opt/gluu/bin/jetty10CompatibleWar.py` to update it to conform jetty 10.
```
$ ./jetty10CompatibleWar.py -in-file[Downloaded server] -out-file[Downloaded server]
example 
$ ./jetty10CompatibleWar.py -in-file /opt/gluu/jetty/oxauth/webapps/4.4.0.sp1/oxauth-server-4.4.0.sp1.war -out-file /opt/gluu/jetty/oxauth/webapps/4.4.0.sp1/oxauth.war
```
 - Stop your **oxauth** service `systemctl stop oxauth`

 - Replace JettyCompatible war file at `/opt/gluu/jetty/oxauth/webapps/oxauth.war`

#### Add External Dependency

Follow [this](https://github.com/GluuFederation/oxAuth/tree/master/Server/integrations/duo-universal-prompt) doc to: 
  - Add the duo-universal Dependency to your oxAuth at`/opt/gluu/jetty/oxauth/custom/libs/*.jar`
  - Register custom libs in oxauth.xml `/opt/gluu/jetty/oxauth/webapps/oxauth.xml`

Start the **oxauth** service `systemctl start oxauth`

### Add Custom Script
- Navigate to `Configuration` > `Person Authentication Scripts`.
   Add new custom script for the 2 factor authentication using DUO and Passport credentials.  

- Add the following Custom Property ( key/value pairs ): 
   - For DUO security 
      - `client_id`
      - `client_secret`
      - `api_hostname` 
   - For Passport social
      -  `key_store_file`
      -  `key_store_password`

- Enable and save.
- *NOTE*: you have to make sure that your `passport_social` and/or `passport_saml` + `Duo Universal` scripts are enabled. This is a combine operation so three scripts must have to runn successfully. 

- A successful configuration should throw snippet like below in `/opt/gluu/jetty/oxauth/oxauth_script.log`

    ```
    2024-06-12 17:56:26,937 INFO  [oxAuthScheduler_Worker-4] [org.gluu.service.PythonService$PythonLoggerOutputStream] (PythonService.java:243) - Passport. init. Initialization success
    2024-06-12 17:56:26,937 INFO  [oxAuthScheduler_Worker-4] [org.gluu.service.PythonService$PythonLoggerOutputStream] (PythonService.java:243) - Duo-Universal. Initialization
    2024-06-12 17:56:26,937 INFO  [oxAuthScheduler_Worker-4] [org.gluu.service.PythonService$PythonLoggerOutputStream] (PythonService.java:243) - Duo-Universal. Initialized successfully
    2024-06-12 17:56:26,937 INFO  [oxAuthScheduler_Worker-4] [org.gluu.service.PythonService$PythonLoggerOutputStream] (PythonService.java:243) - Passport. and Duo-Universal Initialized successfully
    2024-06-12 17:56:26,941 TRACE [oxAuthScheduler_Worker-4] [org.gluu.service.custom.script.CustomScriptManager] (CustomScriptManager.java:134) - Last finished time '2024-06-12T17:56:26.941+0000'
    ```

### Test

To test your setup always use incognito or new browser. 

 - Go to `Manage Authentication` > `Default Authentication Method`
 - Change `oxTrust ACR` to "DuoPassportCombine" ( or whichever name you supplied )
 - `Update`
 - Test
