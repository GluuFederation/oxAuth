### Overview
For authorization perspective in our login page we need to access language for our user.
Here we pass language as a customAttribute and access this language 
from login.xhtml pages.
So for that we 
have to need follow three steps

1. Add [this](BasicLanguageAccessFromLoginPage.py) custom script in `Person Authentication` section

2. Add `language` key - Patch to file with language.

   Example: `/etc/certs/language.json`

   See demo [file](language.json)

3. Add [this](../../src/main/webapp/auth/customLanguage/login.xhtml) html file inside the custom page directory.

   Example: `/opt/gluu/jetty/oxauth/custom/pages/auth/customLanguage/login.xhtml`

Enable the script and check through login with this custom authentication method.
