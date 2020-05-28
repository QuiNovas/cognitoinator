#!/usr/bin/env python3.8
from logging import getLogger, INFO
from os import environ
from boto3 import client, set_stream_logger
from botocore import utils, UNSIGNED
from botocore.exceptions import ClientError
from botocore.config import Config

set_stream_logger(name="botocore")
logger = getLogger("botocore")
logger.setLevel(INFO)

def CognitoLogin(retry=True):
    if "AWS_REFRESH_TOKEN" in environ and environ["AWS_REFRESH_TOKEN"]:
        AUTH_FLOW = "REFRESH_TOKEN_AUTH"
        AUTH_PARAMETERS = {"REFRESH_TOKEN": environ["AWS_REFRESH_TOKEN"]}
    else:
        AUTH_FLOW = "USER_PASSWORD_AUTH"
        AUTH_PARAMETERS = {"USERNAME": environ["COGNITO_USERNAME"], "PASSWORD": environ["COGNITO_PASSWORD"]}

    idp = client("cognito-idp", region_name=environ["AWS_REGION"], config=Config(signature_version=UNSIGNED))
    try:
        auth = idp.initiate_auth(
            AuthFlow=AUTH_FLOW,
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata={"UserPoolId": environ["COGNITO_USER_POOL_ID"]}
        )["AuthenticationResult"]
        environ["AWS_REFRESH_TOKEN"] = auth["RefreshToken"]
        return auth["IdToken"]
    except (Exception, ClientError) as e:
        logger.error(e)
        if "AWS_REFRESH_TOKEN" in environ: del environ["AWS_REFRESH_TOKEN"]
        if retry:
            return CognitoLogin(retry=False)

def GetWebIdentityToken():
    idToken = CognitoLogin()
    idp = client("cognito-identity", region_name=environ["AWS_REGION"])
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
        "COGNITO_IDENTITY_POOL_ID"
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
        logger.info("Fetching credentials with Cognito.")
        token = GetWebIdentityToken()
    else:
        with self._open(self._web_identity_token_path) as token_file:
            token = token_file.read()
    return token


if "AWS_REGION" not in environ: environ["AWS_REGION"] = "us-east-1"
utils.IsCognitoUser = IsCognitoUser
utils.CognitoLogin = CognitoLogin
utils.GetWebIdentityToken = GetWebIdentityToken
utils.FileWebIdentityTokenLoader.__call__ = FileWebIdentityTokenLoader__call__
if IsCognitoUser():
    environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = " "
