# Casa authentication script

Gluu Casa is a self-service web portal for end-users to manage authentication and authorization preferences for their account in Gluu Server. Click [here](https://casa.gluu.org) to learn more about Casa.

Specifically, Casa features a custom script that is aligned with how the application is configured by the administrator. This means the real potential of the script is perceived in the context of an actual casa deployment. The behavior of the script depends on a variety of settings (specially 2FA-related) that can be tweaked using Casa's administration console or via the configuration API.

Among others, Casa performs actions such as:

- Identification of user device 
- Geolocation of user IP
- Determine whether 2FA should take place
- Compute suitable 2FA mechanisms the user can be prompted depending on the context
        
## Required files

The following are the assets involved in casa authentication script:

- Main script: `https://github.com/GluuFederation/community-edition-setup/blob/version_<version>/static/extension/person_authentication/Casa.py`
- Dependant scripts: `https://github.com/GluuFederation/community-edition-setup/tree/version_<version>/static/casa/scripts`. These are bundled with a default installation; more scripts may be required depending on the authentication mechanisms to support. Gluu installer already copies the default scripts in their destination: `/opt/gluu/python/libs`
- XHTML templates: `https://github.com/GluuFederation/oxAuth/tree/version_<version>/Server/src/main/webapp/casa`. More files may be required depending on the authentication mechanisms to support. These files are already hosted by oxAuth web application.

Note: to locate the files that match your Gluu installation replace `<version>` with the (semantic) version of your Server. 

## Configuration properties 

For the main script:

|Name|Description|Sample value|
|-|-|-|
|`mobile_methods`|Optional. Click [here]( https://www.gluu.org/docs/casa/administration/2fa-basics/#associated-strength-of-credentials)|otp, twilio_sms, super_gluu|
|`2fa_requisite`|Optional. Click [here]( https://gluu.org/docs/casa/administration/2fa-basics/#forcing-users-to-enroll-a-specific-credential-before-2fa-is-available)|`true`|
|`supergluu_app_id`|U2F application ID used by SuperGluu enrollments made using Casa, if any|`https://<your-host-name>/casa`|
|`u2f_app_id`|U2F application ID used by FIDO (u2f) enrollments made using Casa, if any|`https://<your-host-name>`|

Auxiliary scripts require properties on their own. You can visit [this](https://www.gluu.org/docs/gluu-server/authn-guide/intro/) page to locate specific pages for every authentication method.

## About the authentication flow

Casa script orchestrates a 2FA flow by delegating specific implementation details of authentication methods to other  scripts. This allows the flow to present users with alternatives in case some credential is not working as expected or is lost. Specific behavior depends on how Casa application is parameterized, please see ["About Two-Factor Authentication"](https://gluu.org/docs/casa/administration/2fa-basics/) for an introduction.

An important restriction to account is that users must present a username and password combination before any form of strong authentication can take place in the flow.

### Adding authentication mechanisms (new factors)

If the method you want to add is already supported out-of-the-box, it is a matter of enabling it: Casa's admin console [doc page](https://gluu.org/docs/casa/administration/admin-console/#enabled-methods) has the required steps. If you are planning to onboard a different mechanism more work is required. In that case, we suggest reading [this page](https://gluu.org/docs/casa/developer/authn-methods/) of Casa's developer guide.

## Flow look&feel

Casa flow pages inherit many of the design elements already set in the [custom branding](https://gluu.org/docs/casa/plugins/custom-branding/) plugin. Changes in design elements such as color scheme or custom CSS rules should take effect in flow pages immediately.

If you require a full customization of the look and feel you have to modify the flow pages. Follow [this](https://gluu.org/docs/gluu-server/operation/custom-design/) as a guide. Account relevant pages are located in `casa` folder of oxAuth war.

