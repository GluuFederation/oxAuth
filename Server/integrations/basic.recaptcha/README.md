# Basic login with Google Recaptcha Validation

1. Add [this](BasicRecaptchaExternalAuthenticator.py) custom script in `Person Authentication` section

2. Add `credentials_file` key - Patch to file with reCAPTCHA credentials.

   Example: `/etc/certs/cert_creds.json`

   See demo [file](cert_creds.json)

3. Add [this](../../src/main/webapp/auth/recaptcha/login.xhtml) html file inside the custom page directory.

   Example: `/opt/gluu/jetty/oxauth/custom/pages/auth/recaptcha/login.xhtml`

Enable the script and check through login with this custom authentication method.
