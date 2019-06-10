1. Append the properties from properties-file to /opt/gluu/jetty/oxauth/webapps/oxauth/WEB-INF/classes/oxauth.properties
2. Goto Configuration --> Manage custom scripts --> Add custom script
3. Add following properties
   iw_cert_store_type = "pkcs12"   
   iw_cert_path = "/etc/certs/Gluu_dev.p12"  
   iw_creds_file = "/etc/certs/iw_creds.json"  
4. In this path - /etc/certs/ ; place inwebo's certificate which can be downloaded from the admin console. Select file type as pkcs12
5. In the iw_creds.json file put the password of the certificate file against CERT_PASSWORD (In the future we can encrypt this. For now it is plain text)
