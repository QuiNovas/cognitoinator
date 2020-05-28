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

**USAGE**:
The only requirement is to have the above mentioned env vars in place before
importing. Cognito credentials will have the last precedence in the credential
provider chain. This means that providing a default profile or IAM credentials
via env vars will be considered first when boto3 looks for credentials. If one or
more, but not all, of the COGNITO env vars above are found an exception will
be raised.

.. code-block:: python

  import boto3
  import CognitoIamProvider

  client = boto3.client("s3")
  client.list_buckets()
