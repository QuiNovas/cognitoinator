#!/usr/bin/env python3.8

import logging
from os import environ
import boto3
import botocore
from botocore import UNSIGNED
from botocore.exceptions import ClientError
from botocore.config import Config

boto3.set_stream_logger(name="botocore", level=logging.INFO)
boto3.set_stream_logger(name="boto3", level=logging.INFO)
logging.getLogger("boto3")
botoLogger = logging.getLogger("boto3")
botocoreLogger = logging.getLogger("botocore")

def CognitoLogin():
    if "AWS_REGION" not in environ: environ["AWS_REGION"] = "us-east-1"
    if "AWS_REFRESH_TOKEN" in environ and environ["AWS_REFRESH_TOKEN"]:
        AUTH_FLOW = "REFRESH_TOKEN_AUTH"
        AUTH_PARAMETERS = {"REFRESH_TOKEN": environ["AWS_REFRESH_TOKEN"]}
    else:
        AUTH_FLOW = "USER_PASSWORD_AUTH"
        AUTH_PARAMETERS = {"USERNAME": environ["COGNITO_USERNAME"], "PASSWORD": environ["COGNITO_PASSWORD"]}

    idp = boto3.client("cognito-idp", region_name=environ["AWS_REGION"], config=Config(signature_version=UNSIGNED))
    return idp.initiate_auth(
        AuthFlow=AUTH_FLOW,
        AuthParameters=AUTH_PARAMETERS,
        ClientId=environ["COGNITO_APP_ID"],
        ClientMetadata={"UserPoolId": environ["COGNITO_USER_POOL_ID"]}
    )

def GetWebIdentityToken():
    try:
        auth = CognitoLogin()
        environ["AWS_REFRESH_TOKEN"] = auth["AuthenticationResult"]["RefreshToken"]
    except (Exception, ClientError) as e:
        botocoreLogger.error(e)
        del environ["AWS_REFRESH_TOKEN"]

    idToken = auth["AuthenticationResult"]["IdToken"]
    idp = boto3.client("cognito-identity", region_name="us-east-1")
    identityId = idp.get_id(
        IdentityPoolId=environ["COGNITO_IDENTITY_POOL_ID"],
        Logins={f"""cognito-idp.us-east-1.amazonaws.com/{environ["COGNITO_USER_POOL_ID"]}""": idToken}
    )["IdentityId"]

    token = idp.get_open_id_token(
        IdentityId=identityId,
        Logins={f"""cognito-idp.{environ["AWS_REGION"]}.amazonaws.com/{environ["COGNITO_USER_POOL_ID"]}""": idToken}
    )["Token"]

    return token

def IsCognitoUser():
    envList = [
        "COGNITO_APP_ID",
        "COGNITO_PASSWORD",
        "COGNITO_USERNAME",
        "COGNITO_USER_POOL_ID",
    ]
    missing = [x for x in envList if x not in environ]
    if missing and missing != envList:
        raise Exception(f"""
            It looks like you want to use Cognito credentials for role switching,
            but you are missing some environment variables. Missing:
            {", ".join(missing)}
        """)
    return bool(not missing)

def FileWebIdentityTokenLoader__call__(self):
    if IsCognitoUser():
        botocoreLogger.debug("""
            Fetching credentials using Cognito OpenId token
        """)
        token = GetWebIdentityToken()
    else:
        with self._open(self._web_identity_token_path) as token_file:
            token = token_file.read()
    return token

botocore.utils.IsCognitoUser = IsCognitoUser
botocore.utils.CognitoLogin = CognitoLogin
botocore.utils.GetWebIdentityToken = GetWebIdentityToken
botocore.utils.FileWebIdentityTokenLoader.__call__ = FileWebIdentityTokenLoader__call__
if botocore.utils.IsCognitoUser():
    environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = " "
else:
    auth = CognitoLogin()
