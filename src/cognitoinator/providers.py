#!/usr/bin/env python3.8
from copy import deepcopy
from threading import Thread
from time import sleep
from io import (
    StringIO,
    TextIOBase
)
from typing import (
    Callable,
    Union,
    Optional
)
from os import environ
import datetime
import json
from logging import getLogger
from dateutil.tz import tzlocal
from dateutil.parser import parse
from boto3 import client
from botocore import UNSIGNED
from botocore.config import Config
from botocore.credentials import (
    CredentialProvider,
    RefreshableCredentials
)
from warrant.aws_srp import AWSSRP

LOGGER = getLogger()
LOGGER.setLevel(environ.get("COGNITO_LOG_LEVEL", "INFO"))


def raise_for_invalid_auth_flow(flow: str):
    allowed_flows = [
        "classic",
        "enhanced"
    ]
    if flow not in allowed_flows:
        raise ValueError(f"Auto flow must be one of {','.join(allowed_flows)}")


def raise_for_invalid_auth_type(auth_type: str):
    allowed_types = [
        "user_srp",
        "user_password"
    ]
    if auth_type not in allowed_types:
        raise ValueError(f"Auth type must be one of {','.join(allowed_types)}")


def get_cognito_config_from_env() -> dict:
    envList = [
        "COGNITO_APP_ID",
        "COGNITO_PASSWORD",
        "COGNITO_USERNAME",
        "COGNITO_USER_POOL_ID",
    ]
    missing = [x for x in envList if x not in environ]
    for e in envList:
        if e not in environ:
            raise Exception(
                f"""
                It looks like you want to use Cognito credentials for role switching,
                but you are missing some environment variables. Missing:
                {e}
            """)
    if not missing:
        res = {
            "app_id": environ["COGNITO_APP_ID"],
            "password": environ["COGNITO_PASSWORD"],
            "username": environ["COGNITO_USERNAME"],
            "user_pool_id": environ["COGNITO_USER_POOL_ID"],
            "identity_pool_id": environ.get("COGNITO_IDENTITY_POOL_ID", " "),
            "role_arn": environ.get("COGNITO_ROLE_ARN") or environ.get("AWS_ROLE_ARN"),
            "role_session_name": environ.get("COGNITO_ROLE_SESSION_NAME"),
            "auth_flow": environ.get("COGNITO_AUTH_FLOW", "enhanced"),
            "metadata": json.loads(environ.get("COGNITO_METADATA", "{}")),
            "role_expiry_time": int(environ.get("COGNITO_ROLE_EXPIRY_TIME", "900"))
        }
    else:
        res = {}
    return res


def get_cognito_config(config: dict) -> dict:
    opt_list = [
        "app_id",
        "password",
        "username",
        "user_pool_id"
    ]
    missing = [x for x in opt_list if x not in config]
    config["auth_flow"] = config.get("auth_flow") or "enhanced"
    config["metadata"] = config.get("metadata", {})
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
    def __init__(self, cache: Union[TextIOBase, str]):
        self.cache = cache
        if (
            isinstance(self.cache, TextIOBase)
            and hasattr(self.cache, "seek")
            and hasattr(self.cache, "truncate")
        ):
            self.json_writer = self.__io_writer
            self.json_loader = self.__io_loader
        elif isinstance(self.cache, str):
            self.raise_for_file_error()
            self.json_writer = self.__file_writer
            self.json_loader = self.__file_loader
        else:
            raise TypeError("TokenCache expects first argument to be either a filename as a string or a seekable, truncatable file-like object")

    def raise_for_file_error(self):
        try:
            with open(self.cache, "r") as _:
                pass
        except Exception as e:
            raise Exception("TokenCache: Invalid cache file") from e

    def cache_tokens(self, tokens: dict):
        if isinstance(tokens.get("token_expires"), datetime.datetime):
            tokens["token_expires"] = str(tokens["token_expires"])

        self.json_writer(tokens)

    def __io_writer(self, data: dict):
        self.cache.seek(0)
        self.cache.truncate()
        self.cache.write(json.dumps(data))
        self.cache.seek(0)

    def __io_loader(self) -> dict:
        self.cache.seek(0)
        # We use read() instead of get_value() even if we are using StringIO because
        # all TextIO objects have read()
        res = self.cache.read()
        # Clean up for the next guy
        self.cache.seek(0)
        return json.loads(res) or {}

    def __file_writer(self, data: dict):
        with open(self.cache, "w") as f:
            json.dump(data, f)

    def __file_loader(self) -> dict:
        with open(self.cache, "r") as f:
            return json.load(f) or {}

    @property
    def tokens(self) -> dict:
        try:
            tokens = self.json_loader()
        except json.decoder.JSONDecodeError as e:
            if e.msg == "Expecting value":
                tokens = {}
            else:
                raise Exception("TokenCache: Could not decode cache values") from e

        return tokens

    def delete_token(self, token: str):
        cur_tokens = self.tokens
        try:
            del cur_tokens[token]
        except KeyError as e:
            raise KeyError(f"TokenCache.delete_token: {e}") from e

        self.cache_tokens(cur_tokens)

    def set_token(self, key, val):
        self.cache_tokens({
            **self.tokens,
            key: val
        })


class TokenFetcher():
    def __init__(
        self,
        *,
        auth_type: str = "user_srp",
        config: dict = {},
        region_name: Optional[str] = None,
        server: bool = False,
        token_cache: Optional[Union[TextIOBase, str]] = None,
        non_blocking: bool = False
    ):
        raise_for_invalid_auth_type(auth_type)

        self.non_blocking = non_blocking

        if token_cache is None:
            io_obj = StringIO()
            token_cache = TokenCache(io_obj)
        else:
            token_cache = TokenCache(token_cache)

        self.provider = CognitoIdentity(
            auth_type=auth_type,
            config=config,
            region_name=region_name,
            token_cache=token_cache
        )

        self.provider.token_cache = token_cache

        if non_blocking:
            Thread(target=self.provider.cognito_login, daemon=True)
        else:
            if self.is_expired(self.provider.token_cache.tokens.get("token_expires")):
                self.provider.cognito_login()

        LOGGER.debug(self.provider.token_cache.tokens)

        if server:
            self.start_server()

    def is_expired(self, expires) -> bool:
        now = datetime.datetime.now(tzlocal())
        margin = datetime.timedelta(seconds=30)
        if not expires:
            return True
        else:
            return now > parse(expires) - margin

    def fetch(self) -> dict:
        self.provider.cognito_login()
        return self.provider.token_cache.tokens

    @property
    def tokens(self) -> dict:
        return self.provider.token_cache.tokens

    @property
    def id_token(self) -> str:
        return self.provider.token_cache.tokens["id_token"]

    @property
    def access_token(self) -> str:
        return self.provider.token_cache.tokens["access_token"]

    @property
    def refresh_token(self) -> str:
        return self.provider.token_cache.tokens["refresh_token"]

    @property
    def expires(self) -> str:
        return self.provider.token_cache.tokens["token_expires"]

    def login_loop(self):
        while True:
            # while datetime.datetime.now(tzlocal()) > parse(self.provider.token_cache.tokens["token_expires"]) - datetime.timedelta(seconds=30):
            if self.is_expired(self.provider.token_cache.tokens["token_expires"]):
                self.provider.cognito_login()
            sleep(5)

    def start_server(self):
        if self.non_blocking:
            Thread(target=self.login_loop, daemon=True).start()
        else:
            self.login_loop()


class CognitoIdentity(CredentialProvider):
    METHOD = 'cognito-identity'
    CANONICAL_NAME = 'customCognitoIdentity'
    api_credential_expiration = None
    auth = None
    tz = datetime.datetime.now(tzlocal())
    STS = None
    IDP = None

    def __init__(
        self,
        *,
        auth_type: str = "user_srp",
        config: dict = {},
        token_cache: TokenCache,
        region_name: str = None
    ):
        super().__init__(self)

        raise_for_invalid_auth_type(auth_type)
        self.profile_credentials = None
        self.token_cache = token_cache

        if config:
            self.config = get_cognito_config(config)
        else:
            self.config = get_cognito_config_from_env()
        self.config["region_name"] = region_name or config.get("region") or environ.get("AWS_DEFAULT_REGION")

        self.IDP = client(
            "cognito-idp",
            region_name=self.config["region_name"],
            config=Config(signature_version=UNSIGNED)
        )

        self.IDENTITY = client("cognito-identity", region_name=self.config["region_name"])

        if self.config["auth_flow"] == "classic":
            self.STS = client("sts")
            self.COGNITO_IDP = client("cognito-idp", region_name=self.config["region_name"])

        if "refresh_token" not in self.token_cache.tokens:
            self.token_cache.set_token("refresh_token", None)

        auth_type = auth_type or environ.get("COGNITO_AUTH_TYPE", "user_srp")
        if auth_type == "user_srp":
            self._auth_func = self._srp_auth
        elif auth_type == "user_password":
            self._auth_func = self._password_auth

    def load(self) -> Union[RefreshableCredentials, None]:
        if self.config:
            fetcher = self._create_credentials_fetcher()
            credentials = fetcher(time_as_string=False)
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

    def _login(self) -> dict:
        return self._auth_func()

    def refresh_auth(self) -> dict:
        self.cognito_login()
        return self.token_cache.tokens

    def cognito_login(self) -> str:
        if self.token_cache.tokens.get("refresh_token") is not None:  # If we have a refresh token use it
            LOGGER.debug("cognito_login: Found refresh token.")
            auth = self._refresh_auth()
            if not auth:
                try:
                    self.token_cache.delete_token("refresh_token")
                except Exception:
                    pass
                auth = self._login()
        else:
            auth = self._login()
            LOGGER.debug("cognito_login: Running fresh login")

        # Get the datetime that the token expires in - 1 minute just to be safe
        diff = auth["ExpiresIn"] - 1
        expires_in = datetime.datetime.now(tzlocal()) + datetime.timedelta(seconds=diff)

        self.token_cache.cache_tokens({
            "id_token": auth["IdToken"],
            "access_token": auth["AccessToken"],
            "token_expires": str(expires_in),
            "refresh_token": auth["RefreshToken"]
        })

        return auth["IdToken"]

    def _srp_auth(self) -> dict:
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

        return auth

    def _password_auth(self) -> dict:
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

    def _refresh_auth(self) -> dict:
        LOGGER.debug("Refreshing auth")
        LOGGER.debug(f"Using Refresh Token {self.token_cache.tokens['refresh_token']}")
        AUTH_PARAMETERS = {"REFRESH_TOKEN": self.token_cache.tokens["refresh_token"]}
        try:
            auth = self.IDP.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=AUTH_PARAMETERS,
                ClientId=self.config["app_id"],
                ClientMetadata=self.config.get("metadata"),
            )["AuthenticationResult"]

            auth["RefreshToken"] = self.token_cache.tokens["refresh_token"]
            return auth
        except self.IDP.exceptions.NotAuthorizedException as e:
            if e.response["Error"]["Message"] == "Refresh Token has expired":
                LOGGER.warning("refresh_auth: Refresh token has expired. Need a fresh login")
            else:
                LOGGER.error(f"Error while refreshing auth: {e}. You may want to disable device tracking if enabled as it can interfere with using refresh tokens.")

    def _create_credentials_fetcher(self) -> Callable:

        def fetch(time_as_string: bool = True) -> dict:
            LOGGER.debug("Checking credentials....")

            # Get a new idToken if this one has expired
            if self.token_cache.tokens.get("id_token") is None or datetime.datetime.now(tzlocal()) > parse(self.token_cache.tokens["token_expires"]):
                LOGGER.debug("Retreiving new Cognito tokens.")
                id_token = self.cognito_login()
            else:
                id_token = self.token_cache.tokens["id_token"]

            try:
                identityId = self.IDENTITY.get_id(
                    IdentityPoolId=self.config["identity_pool_id"],
                    Logins={f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": id_token}
                )["IdentityId"]

            except self.IDENTITY.exceptions.NotAuthorizedException as e:
                LOGGER.info(f"LOGIN ERROR: {e}")
                self.token_cache.tokens["id_token"] = None
                fetch()

            if self.config["auth_flow"] == "classic":
                LOGGER.debug("Using classic auth flow....")
                token = self.IDENTITY.get_open_id_token(
                    IdentityId=identityId,
                    Logins={
                        f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": self.token_cache.tokens["id_token"]
                    }
                )["Token"]

                if self.config.get("role_session_name") is None:
                    attributes = self.COGNITO_IDP.get_user(
                        AccessToken=self.token_cache.tokens["access_token"]
                    )["UserAttributes"]
                    sub = [
                        x["Value"] for x in attributes
                        if x["Name"] == "sub"
                    ][0]

                    self.config["role_session_name"] = sub

                opts = {
                    "WebIdentityToken": token,
                    "DurationSeconds": int(self.config.get("role_expiry_time", "900")),
                    "RoleSessionName": self.config["role_session_name"],
                    "RoleArn": self.config["role_arn"]
                }

                credentials = self.STS.assume_role_with_web_identity(**opts)
                credentials["Credentials"]["SecretKey"] = credentials["Credentials"]["SecretAccessKey"]
            else:
                opts = {
                    "IdentityId": identityId,
                    "Logins": {f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": id_token}
                }
                if self.config.get("role_arn"):
                    opts["CustomRoleArn"] = self.config.get("role_arn")

                credentials = self.IDENTITY.get_credentials_for_identity(**opts)

            # We want to refresh whenever either the id token or iam is about to expire, whichever comes first
            if not self.token_cache.tokens.get("token_expires"):
                expire_time = credentials["Credentials"]["Expiration"]
            elif parse(self.token_cache.tokens["token_expires"]) < credentials["Credentials"]["Expiration"]:
                expire_time = parse(self.token_cache.tokens["token_expires"])
            else:
                expire_time = credentials["Credentials"]["Expiration"]

            # When we call load() expiry_time has to be a datetime, when we are called by RefreshableCredentials expiry_time needs
            # to be a string. I think its ugly myself. Open to suggestions.
            creds = {
                "access_key": credentials["Credentials"]["AccessKeyId"],
                "secret_key": credentials["Credentials"]["SecretKey"],
                "token": credentials["Credentials"]["SessionToken"],
                "expiry_time": str(expire_time) if time_as_string else expire_time
            }

            self.profile_credentials = {
                "Version": 1,
                "AccessKeyId": creds["access_key"],
                "SecretAccessKey": creds["secret_key"],
                "SessionToken": creds["token"],
                "Expiration": str(creds["expiry_time"])
            }

            return creds

        return fetch
