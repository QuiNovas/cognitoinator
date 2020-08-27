============================
cognito-assume-role
============================

Makes boto3 fetch temporary credentials using Federated Web Identities for Cognito users
Requires the following (pretty self explanatory) env vars:

* COGNITO_USERNAME
* COGNITO_PASSWORD
* COGNITO_USER_POOL_ID
* COGNITO_IDENTITY_POOL_ID
* COGNITO_APP_ID
* AWS_ROLE_ARN (Used by boto3 CredentialProvider)

Currently supports USER_SRP_AUTH and USER_PASSWORD_AUTH using standard Cognito auth flow.
Custom auth flows or administrative auth are not currently supported although I suppose
you could monkey patch the needed code.

**USAGE**:
The only requirement is to have the above mentioned env vars in place before
importing. Cognito credentials will have the last precedence in the credential
provider chain. This means that providing a default profile or IAM credentials
via env vars will be considered first when boto3 looks for credentials. If one or
more, but not all, of the COGNITO env vars above are found an exception will
be raised.

**For USER_SRP_AUTH**

.. code-block:: python

  import boto3
  from cognito_assume_role import user_srp

  client = boto3.client("s3")
  client.list_buckets()


**For USER_PASSWORD_AUTH**

.. code-block:: python

  import boto3
  from cognito_assume_role import user_password

  client = boto3.client("s3")
  client.list_buckets()
