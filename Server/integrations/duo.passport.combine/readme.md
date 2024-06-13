## DUO-Passport multiAuth set up [ Work in progress ... ] 

This script allow users to use Duo as two factor in a Passport enabled Gluu Server. 
There are two options in a Passport enabled Gluu Server: 
  - oxAuth login ( left side )
  - Passport login ( right side )

This 

### Download oxAuth 
Get `oxauth.war` from https://maven.gluu.org/maven/org/gluu/oxauth-server/4.4.0.sp1/oxauth-server-4.4.0.sp1.war

### Jetty Compatible
By default old war files are for version 9. As result it apply small changes in war file to run it correctly under jetty 10.

Run `/opt/gluu/bin/jetty10CompatibleWar.py` to update it to conform jetty 10.
```
$ ./jetty10CompatibleWar.py -in-file[Downloaded server] -out-file[Downloaded server]
example 
$ ./jetty10CompatibleWar.py -in-file /opt/gluu/jetty/oxauth/webapps/4.4.0.sp1/oxauth-server-4.4.0.sp1.war -out-file /opt/gluu/jetty/oxauth/webapps/4.4.0.sp1/oxauth.war
```
Stop your **oxauth** service `systemctl stop oxauth`

Replace JettyCompatible war file at `/opt/gluu/jetty/oxauth/webapps/oxauth.war`

### Add External Dependency
Add the duo-universal Dependency to your oxAuth at`/opt/gluu/jetty/oxauth/custom/libs/*.jar`
Register custom libs in oxauth.xml `/opt/gluu/jetty/oxauth/webapps/oxauth.xml`

Start the **oxauth** service `systemctl start oxauth`

### Add Custom Script
1. Navigate to `Configuration` > `Person Authentication Scripts`.
   Add a custom script for the 2 factor authentication using DUO and Passport credentials.  

2. Add the following Custom Property ( key/value pairs ): For DUO security `client_id`, `client_secret`, and `api_hostname`, 
for Passport social `key_store_file`, and `key_store_password`

3. Enable and save.
