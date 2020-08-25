#!/usr/bin/env python3.8

from json import loads
from logging import getLogger, INFO
from os import environ
from boto3 import client, set_stream_logger
from botocore import utils, UNSIGNED
from botocore.exceptions import ClientError
from botocore.config import Config
from warrant.aws_srp import AWSSRP

set_stream_logger(name="botocore")
logger = getLogger("botocore")
logger.setLevel(INFO)

environ["COGNITO_AUTH_TYPE"] = environ.get("COGNITO_AUTH_TYPE", "USER_SRP_AUTH")
environ["AWS_REGION"] = environ.get("AWS_REGION", "us-east-1")
idp = client(
    "cognito-idp",
    region_name=environ["AWS_REGION"],
    config=Config(signature_version=UNSIGNED),
)


def CognitoLogin(retry=True, auth_type=environ["COGNITO_AUTH_TYPE"]):
    def SrpAuth():
        srp = AWSSRP(
            username=environ["COGNITO_USERNAME"],
            password=environ["COGNITO_PASSWORD"],
            pool_id=environ["COGNITO_USER_POOL_ID"],
            client_id=environ["COGNITO_APP_ID"],
            pool_region=environ["AWS_REGION"],
        )

        AUTH_PARAMETERS = {
            "CHALLENGE_NAME": "SRP_A",
            "USERNAME": environ["COGNITO_USERNAME"],
            "SRP_A": srp.get_auth_params()["SRP_A"],
        }

        auth = idp.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )

        response = srp.process_challenge(auth["ChallengeParameters"])

        auth = idp.respond_to_auth_challenge(
            ClientId=environ["COGNITO_APP_ID"],
            ChallengeName="PASSWORD_VERIFIER",
            ChallengeResponses=response,
        )["AuthenticationResult"]

        return auth

    def PasswordAuth():
        AUTH_FLOW = "USER_PASSWORD_AUTH"
        AUTH_PARAMETERS = {
            "USERNAME": environ["COGNITO_USERNAME"],
            "PASSWORD": environ["COGNITO_PASSWORD"],
        }
        auth = idp.initiate_auth(
            AuthFlow=AUTH_FLOW,
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]
        return auth

    def RefreshAuth():
        AUTH_FLOW = "REFRESH_TOKEN_AUTH"
        AUTH_PARAMETERS = {"REFRESH_TOKEN": environ["AWS_REFRESH_TOKEN"]}
        auth = idp.initiate_auth(
            AuthFlow=AUTH_FLOW,
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]
        return auth

    try:
        if environ.get("AWS_REFRESH_TOKEN"):
            auth = RefreshAuth()
        else:
            auth = SrpAuth() if auth_type == "USER_SRP_AUTH" else PasswordAuth()
            environ["AWS_REFRESH_TOKEN"] = auth["RefreshToken"]
        return auth["IdToken"]
    except (Exception, ClientError) as e:
        logger.error(e)
        if "AWS_REFRESH_TOKEN" in environ:
            del environ["AWS_REFRESH_TOKEN"]
        if retry:
            return CognitoLogin(retry=False)


def GetWebIdentityToken():
    idToken = CognitoLogin()
    idp = client("cognito-identity", region_name=environ["AWS_REGION"])
    identityId = idp.get_id(
        IdentityPoolId=environ["COGNITO_IDENTITY_POOL_ID"],
        Logins={
            f"""cognito-idp.{environ['AWS_REGION']}.amazonaws.com/{environ['COGNITO_USER_POOL_ID']}""": idToken
        },
    )["IdentityId"]

    token = idp.get_open_id_token(
        IdentityId=identityId,
        Logins={
            f"""cognito-idp.{environ['AWS_REGION']}.amazonaws.com/{environ['COGNITO_USER_POOL_ID']}""": idToken
        },
    )["Token"]

    return token


def IsCognitoUser():
    assert environ["COGNITO_AUTH_TYPE"] in (
        "USER_SRP_AUTH",
        "USER_PASSWORD_AUTH",
    ), 'COGNITO_AUTH_TYPE must be one of "USER_SRP_AUTH" or "USER_PASSWORD_AUTH"'
    envList = [
        "COGNITO_APP_ID",
        "COGNITO_PASSWORD",
        "COGNITO_USERNAME",
        "COGNITO_USER_POOL_ID",
        "COGNITO_IDENTITY_POOL_ID",
        "COGNITO_AUTH_TYPE",
    ]
    missing = [x for x in envList if x not in environ]
    if missing and missing != envList:
        raise Exception(
            f"""
            It looks like you want to use Cognito credentials for role switching,
            but you are missing some environment variables. Missing:
            {', '.join(missing)}
        """
        )
    return bool(not missing)


def FileWebIdentityTokenLoader__call__(self):
    if IsCognitoUser():
        logger.info("Fetching credentials with Cognito.")
        token = GetWebIdentityToken()
    else:
        with self._open(self._web_identity_token_path) as token_file:
            token = token_file.read()
    return token


utils.IsCognitoUser = IsCognitoUser
utils.CognitoLogin = CognitoLogin
utils.GetWebIdentityToken = GetWebIdentityToken
utils.FileWebIdentityTokenLoader.__call__ = FileWebIdentityTokenLoader__call__
if IsCognitoUser():
    environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = " "  # Nuance of boto3. It is intentional
