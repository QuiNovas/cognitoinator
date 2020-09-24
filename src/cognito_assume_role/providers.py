#!/usr/bin/env python3.8
from threading import Thread
from time import sleep
from io import StringIO
from os import environ
import datetime
import json
from logging import getLogger, INFO
from dateutil.tz import tzlocal
from dateutil.parser import parse
from boto3 import client, set_stream_logger
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.credentials import CredentialProvider, RefreshableCredentials
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
            "metadata": json.loads(environ.get("COGNITO_METADATA", "{}"))
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


class TokenCache:
    def __init__(self, cache):
        self.cache = cache

    def cache_tokens(self, tokens):
        if isinstance(tokens.get("token_expires"), datetime.datetime):
            tokens["token_expires"] = str(tokens["token_expires"])

        if isinstance(self.cache, StringIO):
            self.cache.write(json.dumps(tokens))
            self.cache.seek(0)

        if isinstance(self.cache, str):
            with open(self.cache, "w") as f:
                json.dump(tokens, f)

    @property
    def tokens(self):
        try:
            if isinstance(self.cache, StringIO):
                self.cache.seek(0)
                tokens = json.loads(self.cache.getvalue())
            else:
                with open(self.cache, "r") as f:
                    tokens = json.load(f)
        except json.decoder.JSONDecodeError as e:
            if e.msg == "Expecting value":
                tokens = {}
            else:
                raise e

        return tokens


class TokenFetcher():
    def __init__(self, auth_type="user_srp", config={}, region_name=None, server=False, token_cache=None):
        self.provider = CognitoIdentity(auth_type=auth_type, config=config, region_name=region_name, token_cache=token_cache)
        self.provider.cognito_login()
        if server:
            self.start_server()

    def fetch(self):
        self.provider.cognito_login()
        return self.provider.token_cache.tokens

    @property
    def tokens(self):
        return self.provider.token_cache.tokens

    @property
    def id_token(self):
        return self.provider.cognito_tokens["id_token"]

    @property
    def access_token(self):
        return self.provider.cognito_tokens["access_token"]

    @property
    def refresh_token(self):
        return self.provider.cognito_tokens["refresh_token"]

    @property
    def expires(self):
        return self.provider.cognito_tokens["token_expires"]

    def login_loop(self):
        while True:
            while datetime.datetime.now(tzlocal()) > parse(self.provider.cognito_tokens["token_expires"]) - datetime.timedelta(seconds=30):
                sleep(5)
            self.provider.cognito_login()

    def start_server(self):
        Thread(target=self.login_loop, daemon=True).start()


class CognitoIdentity(CredentialProvider):
    METHOD = 'cognito-identity'
    CANONICAL_NAME = 'customCognitoIdentity'
    api_credential_expiration = None
    cognito_tokens = {}
    auth = None
    tz = datetime.datetime.now(tzlocal())

    def __init__(self, auth_type="user_srp", config={}, region_name=None, token_cache=None):
        super().__init__(self)
        self.token_cache = token_cache
        self.config = get_cognito_config(config) or get_cognito_config_from_env() or {}
        self.config["region_name"] = region_name or config.get("region") or environ.get("AWS_DEFAULT_REGION")
        self.IDP = client(
            "cognito-idp",
            region_name=self.config["region_name"],
            config=Config(signature_version=UNSIGNED)
        )
        self.IDENTITY = client("cognito-identity", region_name=self.config["region_name"])
        self.cognito_tokens["refresh_token"] = None
        auth_type = auth_type or environ.get("COGNITO_AUTH_TYPE", "user_srp")
        if auth_type == "user_srp":
            self._auth_func = self._srp_auth
        elif auth_type == "user_password":
            self._auth_func = self._password_auth
        else:
            raise Exception("kwarg auth_type must be one of user_srp or user_password")

    def load(self):
        if self.config:
            fetcher = self._create_credentials_fetcher()
            credentials = fetcher(time_as="datetime")
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
        return self._auth_func()

    def refresh_auth(self):
        self.cognito_login()
        return self.cognito_tokens

    def cognito_login(self):
        try:
            if self.cognito_tokens.get("refresh_token"):
                auth = self._refresh_auth()
            else:
                auth = self._login()

            # Get the datetime that the token expires in - 1 minute just to be safe
            expires_in = datetime.datetime.now(tzlocal()) + datetime.timedelta(minutes=auth["ExpiresIn"] - 1)

            self.cognito_tokens = {
                "id_token": auth["IdToken"],
                "access_token": auth["AccessToken"],
                "token_expires": str(expires_in),
                "refresh_token": auth["RefreshToken"]
            }

            self.token_cache.cache_tokens(self.cognito_tokens)
            return auth["IdToken"]

        except (Exception, ClientError) as e:
            logger.info(e)
            del self.cognito_tokens["refresh_token"]
            return self.cognito_login()

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
            ClientMetadata=self.config.get("metadata"),
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
            ClientMetadata=self.config.get("metadata")
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def _refresh_auth(self):
        AUTH_PARAMETERS = {"REFRESH_TOKEN": self.token_cache.tokens["refresh_token"]}
        auth = self.IDP.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=self.config.get("metadata"),
        )["AuthenticationResult"]

        auth["RefreshToken"] = self.cognito_tokens["refresh_token"]

        return auth

    def _create_credentials_fetcher(self):
        def assume_role(time_as="string"):
            # Get a new idToken if this one has expired
            if not self.cognito_tokens.get("id_token") or datetime.datetime.now(tzlocal()) > parse(self.cognito_tokens["token_expires"]):
                logger.info("Retreiving new Cognito tokens.")
                self.cognito_login()

            identityId = self.IDENTITY.get_id(
                IdentityPoolId=self.config["identity_pool_id"],
                Logins={f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": self.cognito_tokens["id_token"]}
            )["IdentityId"]

            opts = {
                "IdentityId": identityId,
                "Logins": {f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": self.cognito_tokens["id_token"]}
            }

            if self.config.get("role_arn"):
                opts["CustomRoleArn"] = self.config.get("role_arn")

            credentials = self.IDENTITY.get_credentials_for_identity(**opts)

            # We want to refresh whenever either the id token or iam is about to expire, whichever comes first
            if not self.cognito_tokens.get("token_expires"):
                expire_time = credentials["Credentials"]["Expiration"]
            elif parse(self.cognito_tokens["token_expires"]) < credentials["Credentials"]["Expiration"]:
                expire_time = parse(self.cognito_tokens["token_expires"])
            else:
                expire_time = credentials["Credentials"]["Expiration"]

            # When we call load() expiry_time has to be a datetime, when we are called by RefreshableCredentials expiry_time needs
            # to be a string. I think its ugly myself. Open to suggestions.
            return {
                "access_key": credentials["Credentials"]["AccessKeyId"],
                "secret_key": credentials["Credentials"]["SecretKey"],
                "token": credentials["Credentials"]["SessionToken"],
                "expiry_time": str(expire_time) if time_as == "string" else expire_time
            }

        return assume_role
