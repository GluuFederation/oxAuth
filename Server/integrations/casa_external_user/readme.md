# CASA with external user [ Work in progress ] 

This script integrate basic_multi_auth ( https://github.com/GluuFederation/oxAuth/tree/master/Server/integrations/basic.multi_auth_conf ) with CASA which allows organization to allow their external users ( who are being pulled or pushed from remote AD or LDAP ) to use CASA. 

## How to use this script: 

 - This feature is only available from 4.5 and above.
 - We need new CASA war to use this script for now:
   - Download war: https://maven.gluu.org/maven/org/gluu/casa/4.5.4.Final/casa-4.5.4.Final.war
   - Update your server with this war.
   - Append new java parameter ( "-Dadmin.lock=/opt/gluu/jetty/casa/.administrable") in `/etc/default/casa`:
     - `JAVA_OPTIONS="-server -Xms128m -Xmx846m -XX:+DisableExplicitGC -Dgluu.base=/etc/gluu -Dserver.base=/opt/gluu/jetty/casa -Dlog.base=/opt/gluu/jetty/casa -Dadmin.lock=/opt/gluu/jetty/casa/.administrable"`
   - Restart oxauth, identity and casa service
 - Use attached script in Person Authentication Script. 
   - in "Custom Property" use this value: 
      - `auth_configuration_file` == `/etc/certs/multi_auth_conf.json`
   

## If SuperGluu....

If you want to use SuperGluu in this whole setup, you have to: 

 - Download SG script from here ( https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_4.5.4/static/casa/scripts/casa-external_super_gluu.py ) and copy it inside `/opt/gluu/python/lib`
 - Make sure to change permission to "jetty:gluu"
 - Restart oxauth service. 
