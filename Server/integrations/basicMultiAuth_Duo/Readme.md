# This script allow BasicMultiAuth and Duo scripts to run together in Gluu v4. 

## Configuration: 

 - Download BasicMultiAuth and Duo script and put them inside /opt/gluu/python/libs/.
    - File name of downloaded basic_multi_auth script is: `BasicMultiAuthConfExternalAuthenticator.py`
    - File name of downloaded duo script is: `DuoExternalAuthenticator.py`
 - Make sure the ownership and permission for these two files are:
 - Restart oxauth one time.
 - Both scripts should be enabled from oxTrust
 - Add third script which is a new one calling both BasicMultiAuth and Duo scripts
 - Enable this new script
 - Change 'Manage Authentication' to new 'BasicMultiAuthDuo' acr.
 - 'BasicMultiAuthDuo' properties:
    - Name: BasicMultiAuthDuo
    - Select SAML ACRs: default, none to select
    - Description: Combination of BasicMultiAuth and Duo
    - Programming Language: Python
    - Level: 100
    - Location Type: Database
    - Interactive: Web
    - Custom property ( key/value ): 
      - auth_configuration_file: /etc/certs/multi_auth_conf.json
      - duo_creds_file: /etc/certs/duo_creds.json
      - duo_host: Provided by Duo
      - audit_attribute: whichever attribute you want to audit
      - duo_group: if there is any special DN or group which should call for duo
  - Add script

