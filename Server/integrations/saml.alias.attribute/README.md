# This script allows you to create a shade of actual attribute and share that reflection to Service Provider / SAML application.  

## Example

We are using a Gluu 4.4.x server and created a mirror attribute named "espejo" which will reflect "mail" attributes value and send that value to target SP as "espejo == support@gluu.org". "support@gluu.org" is actually a mail attribute stored in Gluu Server. 

## Configuration
 - Configure and enable custom attribute `espejo`
 - Use attached script and use that in "IDP Extension". 
   - Log into oxTrust
   - "Other Custom Scripts"
   - "Idp Extension"
      - Name: `attribute_rewirte`
      - Description: `Attribute rewrite script`
      - Programming Language: default ( Jython )
      - Level: default ( 0 )
      - Location Type: default ( Database )
      - Custom property (key/value): 
        - `saml_source_attribute`: mail
        - `saml_target_attribute` : espejo
      - Add script
   - 
 - 
