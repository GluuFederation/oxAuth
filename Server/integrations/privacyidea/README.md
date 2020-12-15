This is the authentication script to authenticate Gluu against privacyIDEA.

# Setup

* Download the jar-with-dependencies from [here](https://github.com/privacyidea/sdk-java/releases).
* Change the name to ``java_sdk.jar`` and put it in ``/opt/gluu-server/opt``.
* Alternatively put the file under any name anywhere in ``/opt/gluu-server/`` and configure the path later.

# Configuration

* Create a new Person Authentication script, choose file and enter the path to the ``.py`` file like explained above or choose database and paste its contents.

* Add a new attribute with the key ``privacyidea_url`` and the url to the privacyIDEA Server as value.

* If the java sdk is not in the above mentioned default location, add the key ``sdk_path`` with the path to the file including its compelete name as value.

#### The following keys are optional (case sensitive!):

* ``realm`` specify a realm that will be appended to each request.
* ``sslverify`` set to ``0`` to disable peer verification.
* ``log_from_sdk`` with any value: enable the logging of the jar.

By default, the password from the first step is verified by the Gluu server and the OTP from the second step is sent to and verified by privacyIDEA.
To use challenge-reponse type token, use the following configuration options:
* ``sendpassword`` set to ``1`` if the password and username from the first step should be sent to the privacyIDEA server. This setting takes precedence over ``triggerchallenge``.
* ``triggerchallenge`` set to ``1`` if challenges for the user should be triggered using the service account.
* ``serviceaccountname`` name of the service account to trigger challenges with.
* ``serviceaccountpass`` password of the service account to trigger challenges with.
* ``serviceaccountrealm`` optionally set the realm in which the service account can be found if it is different from the ``realm`` or default realm.
* ``disablegluupass`` set to ``1`` to disable the password verification of the Gluu server. This can be useful if the password should be verified by privacyIDEA in conjunction with the ``sendpassword`` setting.

* **After finishing the configuration, change the default authentication method to the Person Authentication script you just created.**

#### Logfile

* The logfile for scripts is located at ``/opt/gluu-server/opt/gluu/jetty/oxauth/logs/oxauth_script.log``.
