# CASA with external user [ Work in progress ] 

This script integrate basic_multi_auth ( https://github.com/GluuFederation/oxAuth/tree/master/Server/integrations/basic.multi_auth_conf ) with CASA which allows organization to allow their external users ( who are being pulled or pushed from remote AD or LDAP ) to use CASA. 

## How to use this script: 

 - This feature is only available from 4.5 and above.
 - We need new CASA war to use this script for now:
   - Download war: https://maven.gluu.org/maven/org/gluu/casa/4.5.4.Final/casa-4.5.4.Final.war
   - Update your server with this war. 
 - Use attached script in Person Authentication Script. 
