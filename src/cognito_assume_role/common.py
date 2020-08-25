#!/usr/bin/env python3.8

from json import loads
from logging import getLogger, INFO
from os import environ
from boto3 import client, set_stream_logger
from botocore import utils, UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from warrant.aws_srp import AWSSRP

set_stream_logger(name="botocore")
logger = getLogger("botocore")
logger.setLevel(INFO)

AWS_REGION = environ.get('AWS_REGION', 'us-east-1')
IDP = client(
    "cognito-idp",
    region_name=AWS_REGION,
    config=Config(signature_version=UNSIGNED),
)

IDENTITY = client('cognito-identity', region_name=AWS_REGION)

def is_cognito():
    envList = [
        "COGNITO_APP_ID",
        "COGNITO_PASSWORD",
        "COGNITO_USERNAME",
        "COGNITO_USER_POOL_ID",
        "COGNITO_IDENTITY_POOL_ID",
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

def patch_boto(role):
    def token_loader(self):
        if is_cognito():
            logger.info("Fetching credentials with Cognito.")
            token = role.GetWebIdentityToken()
        else:
            logger.info(f"""Fetched token file: {self._web_identity_token_path}""")
            with open(self._web_identity_token_path) as token_file:
                token = token_file.read()
        return token

    utils.FileWebIdentityTokenLoader.__call__ = token_loader
    utils.IsCognitoUser = is_cognito
    utils.CognitoLogin = role.cognito_login
    utils.GetWebIdentityToken = role.GetWebIdentityToken

class CognitoAssumeRole:
    def __init__(self):
        self.auth = None

    def _login(self):
        """Override this method with the FileWebIdentityTokenLoader of your choice"""
        return self.auth()

    def cognito_login(self):
        try:
            if environ.get("AWS_REFRESH_TOKEN"):
                auth = self.refresh_auth()
            else:
                auth = self._login()
                environ["AWS_REFRESH_TOKEN"] = auth["RefreshToken"]
            return auth["IdToken"]
        except (Exception, ClientError) as e:
            logger.error(e)
            try:
                del environ["AWS_REFRESH_TOKEN"]
                return self.cognito_login()
            except (Exception, ClientError) as e:
                logger.error(e)

    def _srp_auth(self):
        srp = AWSSRP(
            username=environ["COGNITO_USERNAME"],
            password=environ["COGNITO_PASSWORD"],
            pool_id=environ["COGNITO_USER_POOL_ID"],
            client_id=environ["COGNITO_APP_ID"],
            pool_region=AWS_REGION,
        )

        AUTH_PARAMETERS = {
            "CHALLENGE_NAME": "SRP_A",
            "USERNAME": environ["COGNITO_USERNAME"],
            "SRP_A": srp.get_auth_params()["SRP_A"],
        }

        auth = IDP.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )

        response = srp.process_challenge(auth["ChallengeParameters"])

        auth = IDP.respond_to_auth_challenge(
            ClientId=environ["COGNITO_APP_ID"],
            ChallengeName="PASSWORD_VERIFIER",
            ChallengeResponses=response,
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def _password_auth(self):
        AUTH_PARAMETERS = {
            "USERNAME": environ["COGNITO_USERNAME"],
            "PASSWORD": environ["COGNITO_PASSWORD"],
        }
        auth = IDP.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def refresh_auth(self):
        AUTH_PARAMETERS = {"REFRESH_TOKEN": environ["AWS_REFRESH_TOKEN"]}
        auth = IDP.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=environ["COGNITO_APP_ID"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def GetWebIdentityToken(self):
        idToken = self.cognito_login()

        identityId = IDENTITY.get_id(
            IdentityPoolId=environ["COGNITO_IDENTITY_POOL_ID"],
            Logins={
                f"""cognito-idp.{AWS_REGION}.amazonaws.com/{environ['COGNITO_USER_POOL_ID']}""": idToken
            },
        )["IdentityId"]
        token = IDENTITY.get_open_id_token(
            IdentityId=identityId,
            Logins={
                f"""cognito-idp.{AWS_REGION}.amazonaws.com/{environ['COGNITO_USER_POOL_ID']}""": idToken
            },
        )["Token"]

        return token
