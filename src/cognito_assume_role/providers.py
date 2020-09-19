#!/usr/bin/env python3.8
from threading import Thread
from uuid import uuid4
from datetime import datetime, timedelta
from time import sleep
from json import loads
from logging import getLogger, INFO
from os import environ
from boto3 import client, set_stream_logger
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.credentials import CredentialProvider, RefreshableCredentials, JSONFileCache
from warrant.aws_srp import AWSSRP

set_stream_logger(name="botocore")
logger = getLogger("botocore")
logger.setLevel(INFO)


def get_cognito_config_from_env():
    envList = [
        "COGNITO_APP_ID",
        "COGNITO_PASSWORD",
        "COGNITO_USERNAME",
        "COGNITO_USER_POOL_ID",
        "COGNITO_IDENTITY_POOL_ID",
    ]
    missing = [x for x in envList if x not in environ]
    if missing and len(missing) != len(envList):
        raise Exception(
            f"""
            It looks like you want to use Cognito credentials for role switching,
            but you are missing some environment variables. Missing:
            {', '.join(missing)}
        """
        )
    if not missing:
        res = {
            "app_id": environ["COGNITO_APP_ID"],
            "password": environ["COGNITO_PASSWORD"],
            "username": environ["COGNITO_USERNAME"],
            "user_pool_id": environ["COGNITO_USER_POOL_ID"],
            "identity_pool_id": environ["COGNITO_IDENTITY_POOL_ID"],
            "metadata": loads(environ.get("COGNITO_METADATA", "{}"))
        }
    else:
        res = {}

    return res


def get_cognito_config(config):
    opt_list = [
        "app_id",
        "password",
        "username",
        "user_pool_id",
        "identity_pool_id"
    ]
    missing = [x for x in opt_list if x not in config]
    if missing and config:
        raise Exception(
            f"""
            It looks like you want to use Cognito credentials for role switching,
            but you are missing some variables from cognito_credentials file. Missing:
            {', '.join(missing)}
        """
        )
    return config


class TokenFetcher():
    cache_id = str(uuid4())
    cache = JSONFileCache()

    def __init__(self, auth_type="user_srp", config={}, region_name=None, server=False):
        self.provider = CognitoIdentity(auth_type=auth_type, config=config, region_name=region_name)
        self.fetch()
        if server:
            self.start_server()


    def fetch(self):
        self.provider.cognito_login(cache=False)
        self.cache.__setitem__(
            self.cache_id,
            {
                "id_token": self.provider.cognito_id_token,
                "access_token": self.provider.cognito_access_token,
                "token_expires": self.provider.cognito_token_expires,
                "refresh_token": self.provider.cognito_refresh_token
            }
        )

    @property
    def id_token(self):
        try:
            return self.cache.__getitem__(self.cache_id).get("id_token")
        except KeyError:
            logger.debug(f"Could not access cache {self.cache_id}. Possible race condition?")

    @property
    def access_token(self):
        try:
            return self.cache.__getitem__(self.cache_id).get("access_token")
        except KeyError:
            logger.debug(f"Could not access cache {self.cache_id}. Possible race condition?")

    @property
    def refresh_token(self):
        try:
            return self.cache.__getitem__(self.cache_id).get("refresh_token")
        except KeyError:
            logger.debug(f"Could not access cache {self.cache_id}. Possible race condition?")

    @property
    def expires(self):
        try:
            return self.cache.__getitem__(self.cache_id).get("token_expires")
        except KeyError:
            logger.debug(f"Could not access cache {self.cache_id}. Possible race condition?")

    def get_login(self):
        while True:
            while self.provider.cognito_token_expires < datetime.now() - timedelta(seconds=60):
                sleep(5)
            self.provider.cognito_login()
            self.cache.__setitem__(
                "cognito_tokens",
                {
                    "id_token": self.provider.cognito_id_token,
                    "access_token": self.provider.cognito_access_token,
                    "token_expires": self.provider.cognito_token_expires,
                    "refresh_token": self.provider.cognito_refresh_token
                }
            )

    def start_server(self):
        Thread(target=self.get_login, daemon=True).start()


class CognitoIdentity(CredentialProvider):
    METHOD = 'cognito-identity'
    api_credential_expiration = None
    cognito_refresh_token = None
    cognito_id_token = None
    cognito_access_token = None
    cognito_token_expires = None
    auth = None
    cache = JSONFileCache()
    cache_id = str(uuid4())

    def __init__(self, auth_type="user_srp", config={}, region_name=None):
        self.config = get_cognito_config(config) or get_cognito_config_from_env() or {}
        self.config["region_name"] = region_name or config.get("region") or environ.get("AWS_DEFAULT_REGION")

        self.IDP = client(
            "cognito-idp",
            region_name=self.config["region_name"],
            config=Config(signature_version=UNSIGNED)
        )
        self.IDENTITY = client("cognito-identity", region_name=self.config["region_name"])

        auth_type = auth_type or environ.get("COGNITO_AUTH_TYPE", "user_srp")
        if auth_type == "user_srp":
            self.auth_func = self._srp_auth
        elif auth_type == "user_password":
            self.auth_func = self._password_auth
        else:
            raise Exception("kwarg auth_type must be one of user_srp or user_password")

    def load(self):
        if self.config:
            fetcher = self._create_credentials_fetcher()
            credentials = fetcher()
            res = RefreshableCredentials(
                credentials["access_key"],
                credentials["secret_key"],
                credentials["token"],
                credentials["expiry_time"],
                refresh_using=fetcher,
                method=self.METHOD
            )
        else:
            res = None
        return res

    def _login(self):
        return self.auth_func()

    def cognito_login(self, cache=False):
        try:
            if self.config.get("cognito_refresh_token"):
                auth = self.refresh_auth()
            else:
                auth = self._login()

            expires_in = datetime.now() + timedelta(seconds=auth["ExpiresIn"])
            if cache:
                self.cache.__setitem__(
                    self.cache_id,
                    {
                        "id_token": auth["IdToken"],
                        "access_token": auth["AccessToken"],
                        "token_expires": expires_in,
                        "refresh_token": auth["IdToken"]
                    }
                )

            self.cognito_id_token = auth["IdToken"]
            self.cognito_access_token = auth["AccessToken"]
            self.cognito_token_expires = expires_in
            self.cognito_refresh_token = auth["RefreshToken"]

            return auth["IdToken"]
        except (Exception, ClientError) as e:
            logger.info(e)
            try:
                self.cognito_refresh_token = None
                return self.cognito_login()
            except (Exception, ClientError) as e:
                logger.warning(e)

    def _srp_auth(self):
        srp = AWSSRP(
            username=self.config["username"],
            password=self.config["password"],
            pool_id=self.config["user_pool_id"],
            client_id=self.config["app_id"],
            pool_region=self.config["region_name"],
        )

        AUTH_PARAMETERS = {
            "CHALLENGE_NAME": "SRP_A",
            "USERNAME": self.config["username"],
            "SRP_A": srp.get_auth_params()["SRP_A"],
        }

        auth = self.IDP.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=self.config.get("metadata", {}),
        )

        response = srp.process_challenge(auth["ChallengeParameters"])

        auth = self.IDP.respond_to_auth_challenge(
            ClientId=self.config["app_id"],
            ChallengeName="PASSWORD_VERIFIER",
            ChallengeResponses=response,
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def _password_auth(self):
        AUTH_PARAMETERS = {
            "USERNAME": self.config["username"],
            "PASSWORD": self.config["password"]
        }
        auth = self.IDP.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def refresh_auth(self):
        AUTH_PARAMETERS = {"REFRESH_TOKEN": environ["AWS_REFRESH_TOKEN"]}
        auth = self.IDP.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=loads(environ.get("COGNITO_METADATA", "{}")),
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def _create_credentials_fetcher(self):
        def assume_role():
            idToken = self.cognito_login()

            identityId = self.IDENTITY.get_id(
                IdentityPoolId=self.config["identity_pool_id"],
                Logins={
                    f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": idToken
                },
            )["IdentityId"]
            opts = {
                "IdentityId": identityId,
                "Logins": {f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": idToken}
            }

            if environ.get("AWS_ROLE_ARN"):
                opts["CustomRoleArn"] = environ["AWS_ROLE_ARN"]

            credentials = self.IDENTITY.get_credentials_for_identity(**opts)
            return {
                "access_key": credentials["Credentials"]["AccessKeyId"],
                "secret_key": credentials["Credentials"]["SecretKey"],
                "token": credentials["Credentials"]["SessionToken"],
                "expiry_time": credentials["Credentials"]["Expiration"]
            }

        return assume_role
