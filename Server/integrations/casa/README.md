# Casa authentication script

Gluu Casa is a self-service web portal for end-users to manage authentication and authorization preferences for their account in Gluu Server. Click [here](https://casa.gluu.org) to learn more about Casa.

Specifically, Casa features a custom script that is aligned with how the application is configured by the administrator. This means the real potential of the script is perceived in the context of an actual casa deployment. The behavior of the script depends on a variety of settings (specially 2FA-related) that can be tweaked using Casa's administration console or via the configuration API.

## Required files

The following are the assets involved in casa authentication script:

- Main script: `https://github.com/GluuFederation/community-edition-setup/blob/version_<version>/static/extension/person_authentication/Casa.py`
- Dependant scripts: `https://github.com/GluuFederation/community-edition-setup/tree/version_<version>/static/casa/scripts`. These are bundled with a default installation; more scripts may be required depending on the authentication mechanisms to support. Gluu installer already copies the default scripts in their destination: `/opt/gluu/python/libs`
- XHTML templates: `https://github.com/GluuFederation/oxAuth/tree/version_<version>/Server/src/main/webapp/casa`. More files may be required depending on the authentication mechanisms to support. These files are already hosted by oxAuth application

Note: to locate the files that match your Gluu installation replace `<version>` with the (semantic) version of your Server. 

## Configuration properties 

For the main script:

|Name|Description|Sample value|
|-|-|-|
|`mobile_methods`|Click [here]( https://www.gluu.org/docs/casa/administration/2fa-basics/#associated-strength-of-credentials)|otp, twilio_sms, super_gluu|
|supergluu_app_id|U2F application ID used by SuperGluu enrollments made using Casa, if any|`https://<your-host-name>/casa`|
|u2f_app_id|U2F application ID used by FIDO (u2f) enrollments made using Casa, if any|`https://<your-host-name>`|

Auxiliary scripts require properties on their own. You can visit [this](https://www.gluu.org/docs/gluu-server/authn-guide/intro/) page to locate specific pages for every authentication method.
