============================
cognito-assume-role
============================


Currently supports USER_SRP_AUTH and USER_PASSWORD_AUTH using enhanced Cognito auth flow.
Custom auth flows or administrative auth are not currently supported although I suppose
you could monkey patch the needed code. It was written using only public methods exposed by the boto3/botocore
API's to help ensure that changes to boto3 won't break any (what would be otherwise) monkey patched code.
This should also maintain the ability to use this library for your boto3 calls that are not using Cognito within
the same script by simply passing a normal boto3 client credential argument.

**USAGE**:
This module can insert a botocore.credentials.CredentialProvider into the provider chain.
Using this provider we can assume an IAM role through get_credentials_for_identity(). To do this
we provide three functions:
- client (wraps boto3.client())
- resource (wraps boto3.resource())
- Session (wraps boto3.session.Session())

All three of these functions accept all normal boto3 args and kwargs plus some that are specific to this module.
We provide three ways of providing the initial credentials.


**Env vars**
These will take affect before any other credential provider, including the standard env provider that looks for AWS_SECRET_ACCESS_KEY and AWS_ACCESS_KEY_ID.
If one or more of the following non-optional variables are found in environ then we will automatically go to env based credential mapping

- COGNITO_USERNAME
- COGNITO_PASSWORD
- COGNITO_USER_POOL_ID
- COGNITO_IDENTITY_POOL_ID
- COGNITO_APP_ID
- COGNITO_METADATA (Deserialized and passed as ClientMetadata in boto3.client("cognito-idp").initiate_auth()) - Optional
- AWS_ROLE_ARN - Optional


**Profile**
Credential file locations, if not specified, will be resolved in the order of <argument to client>, "COGNITO_CREDENTIALS_FILE", "~/.aws/cognito_credentials".
Config files take the following form:

.. code-block:: toml

  [default]
  username=myusername
  password=***********
  app_id=1234567890
  user_pool_id=abcdefg
  identity_pool_id=us-east-1:1234567890
  region=us-east-1
  metadata={"foo": "bar"}
  auth_type=user_srp


All values except for region and metadata are required if using a profile. Using a profile is done by passing the kwarg "cognito_profile=<profile name>" to client, Session, or resource.

**Direct configuration**

.. code-block:: json

  {
    "username": "myusername",
    "password": "***********",
    "app_id": "1234567890",
    "user_pool_id": "abcdefg",
    "identity_pool_id": "us-east-1:1234567890",
    "region": "us-east-1",
    "metadata": {"foo": "bar"},
    "auth_type": "user_srp"
  }

Same rules apply for required values as when using a profile. Direct configuration is done by passing the config dictionary to kwarg cognito_config when creating a client, resource, or Session.
Note that cognito_profile and cognito_config are mutually exclusive. Trying to use both at once will raise an Assertion exception.


**Auth types**
The client, resource, and Session functions also accept an argument of auth_type. This can be "user_srp" (default) or "user_password".


**Accessing Cognito tokens from a Session**
If creating a Session directly the cognito id, refresh, and access tokens, as well as the expires time are available as properties on the Session object.
Tokens are stored in memory by default, but passing a file name as "token_cache=/file/path.txt" into Session() will write cause the tokens to be written to the specified
file as JSON. Passing a path to a file that does not exist will raise a FileNotFoundError. Passing a path to a file that is not writeable will raise OSError. Properties
to access tokens:

- Session().id_token
- Session().access_token
- Session().refresh_token
- Session().token_expires
- Session().cognito_tokens (All of the above in a dict)

Because of how boto3 generates clients there is no way to access the "parent" session. This means that to use this feature you will need to create a Session()
object and then create your clients/resources off of that Session(). Example:

.. code-block:: python

  from cognito_assume_role import Session

  session = Session()
  s3 = session.s3()
  s3.list_buckets()
  print(session.token_expires)

  # Outputs 2020-09-19T23:17:28CDT


.. code-block:: python

  from cognito_assume_role import TokenFetcher

  s = TokenFetcher()
  # Strings shortened for brevity
  print(s.id_token[-10:-1])
  print(s.access_token[-10:-1])
  print(s.refresh_token[-10:-1])
  print(s.expires)

  """
  Results in:
    6xAb_vMKv
    4Ruc_TB_h
    m3Htft_Op
    2020-09-19T05:16:31
  """


  **Getting Cognito credential tokens without a role**
  If you don't want to assume a role but would still like to access cognito id tokens directly, for instance to make Appsync calls using the requests library, you
  can use the TokenFetcher class. It provides the following properties:

  - tokens (dict): A dictionary containing id_token, access_token, token_expires, and refresh_token
  - id_token
  - access_token
  - refresh_token
  - token_expires

  Methods:
  - fetch(): Updates and returns self.tokens

  All properties are available upon instantiation. The constructor accepts the same kwargs as Session(), along with option "server (bool)". Setting "server=True" will start a background process to keep
  tokens refreshed automatically, which means that your tokens will always be up to date.

  **Example**

  .. code-block:: python

    from cognito_assume_role import TokenFetcher

    cognito_credentials = TokenFetcher()
    print(cognito_credentials)

    print(cognito_credentials.id_token)
    print(cognito_credentials.access_token)
    print(cognito_credentials.token_expires)
    print(cognito_credentials.refresh_token)





**Creating a client that uses a config**

.. code-block:: python

  from cognito_assume_role import client

  client = boto3.client("s3", profile="my_profile")
  client.list_buckets()


**Using resource with env vars and specifying auth_type and region**

.. code-block:: python

  from cognito_assume_role import resource

  resource = boto3.resource("s3", auth_type="user_password", region_name="us-east-2")
  resource.create_bucket(Bucket="my-file-dump-woot-woot")


**Creating a session that we can reuse for multiple clients**

.. code-block:: python

  from cognito_assume_role import Session
  session = Session(auth_type="user_srp", region_name="us-east-2")
  s3 = session.client("s3")
  dynamo = resource("dynamodb")
  table = dynamo.Table("my_table")


**Precedence of CredentialProviders**
The order of resolution for credential providers remains unchanged except for setting environment variables for Cognito will take affect
before any AWS credential environment variables.

**Precedence of arguments**
Any value that can be defined in either an environment variable, explicitly passed as a kwarg ( passed to client, resource, or Session)
or can be part of a config or profile is resolved in the following order:

- explicit arguments
- specified by config or profile
- environment variables
