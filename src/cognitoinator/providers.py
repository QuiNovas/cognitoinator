#!/usr/bin/env python3.8
from threading import Thread
from enum import (
    Enum,
    auto
)
from time import sleep
from io import (
    StringIO,
    TextIOBase
)
from typing import (
    Callable,
    Union,
    Optional,
    NamedTuple
)
from collections import UserDict
from os import environ
import datetime
import json
from logging import getLogger
from dateutil.tz import tzlocal
from dateutil.parser import parse
from boto3 import client
from botocore import UNSIGNED
from botocore.client import BaseClient
from botocore.config import Config as BotoConfig
from botocore.credentials import (
    CredentialProvider,
    RefreshableCredentials
)
from warrant.aws_srp import AWSSRP

LOGGER = getLogger()
LOGGER.setLevel(environ.get("COGNITO_LOG_LEVEL", "INFO"))


class AuthType(Enum):
    user_srp = auto()
    user_password = auto()


class AuthFlow(Enum):
    classic = auto()
    enhanced = auto()


class Config(NamedTuple):
    """ Used to enforce typechecking and requirements for configs """
    app_id: str
    password: str
    username: str
    user_pool_id: str
    region: str = None
    region_name: str = None
    identity_pool_id: str = None
    role_arn: str = None
    auth_flow: str = "enhanced"
    role_session_name: str = None
    metadata: dict = {}
    role_expiry_time: int = 900


class CognitoConfig(UserDict):
    """ Validates a config against Config and returns a UserDict """
    def __init__(self, config):
        # Override config with env vars if they exist
        for x in Config.__annotations__.keys():
            env_key = f"COGNITO_{x.upper()}"
            if val := environ.get(env_key):
                if x == "metadata":
                    val = json.loads(val)
                if x == "role_expiry_time":
                    val = int(val)
                config[x] = val

        if "auth_flow" in config:
            _raise_for_invalid_auth_flow(config["auth_flow"])

        data = Config(**config)._asdict()
        super().__init__(data)

        for k, v in data.items():
            if v is None:
                del self[k]


def _raise_for_invalid_auth_type(auth_type: str) -> None:
    try:
        AuthType[auth_type]
    except KeyError:
        raise TypeError(
            "Unknown auth type {auth_type}. Must be one of 'user_srp' or 'user_password'")


def _raise_for_invalid_auth_flow(flow: str) -> None:
    try:
        AuthType[flow]
    except KeyError:
        raise TypeError(
            "Unknown auth flow {flow}. Must be one of 'classic' or 'enhanced'")


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
            self.__raise_for_file_error()
            self.json_writer = self.__file_writer
            self.json_loader = self.__file_loader
        else:
            raise TypeError("TokenCache expects first argument to be either a filename as a string or a seekable, truncatable file-like object")

    def __raise_for_file_error(self):
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

    def delete_token(self, token: str) -> None:
        cur_tokens = self.tokens
        try:
            del cur_tokens[token]
        except KeyError as e:
            raise KeyError(f"TokenCache.delete_token: {e}") from e

        self.cache_tokens(cur_tokens)

    def set_token(self, key: str, val: str) -> None:
        self.cache_tokens({
            **self.tokens,
            key: val
        })


class TokenFetcher:
    def __init__(
        self,
        *,
        auth_type: str = "user_srp",
        config: Union[CognitoConfig, dict] = {},
        region_name: Optional[str] = None,
        server: bool = False,
        token_cache: Optional[Union[TextIOBase, str]] = None,
        non_blocking: bool = False
    ):

        _raise_for_invalid_auth_type(auth_type)

        self.non_blocking = non_blocking

        if token_cache is None:
            io_obj = StringIO()
            token_cache = TokenCache(io_obj)
        else:
            token_cache = TokenCache(token_cache)

        if not isinstance(config, CognitoConfig):
            config = CognitoConfig(config)

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
            if self.is_expired(self.provider.token_cache.tokens["token_expires"]):
                self.provider.cognito_login()
            sleep(5)

    def start_server(self):
        if self.non_blocking:
            Thread(target=self.login_loop, daemon=True).start()
        else:
            self.login_loop()


class CognitoIdentity(CredentialProvider):
    __METHOD = 'cognito-identity'
    __CANONICAL_NAME = 'customCognitoIdentity'
    api_credential_expiration = None
    auth: dict = None
    tz = datetime.datetime.now(tzlocal())
    __STS: BaseClient = None
    __IDP: BaseClient = None
    __COGNITO_IDP: BaseClient = None
    __IDENTITY: BaseClient = None

    def __init__(
        self,
        *,
        auth_type: str = "user_srp",
        config: Union[CognitoConfig, dict] = {},
        token_cache: TokenCache,
        region_name: str = None
    ):
        super().__init__(self)

        _raise_for_invalid_auth_type(auth_type)
        self.profile_credentials = None
        self.token_cache = token_cache

        if not isinstance(config, CognitoConfig):
            config = CognitoConfig(config)
        self.config = config

        self.config["region_name"] = region_name or config.get("region_name") or config.get("region") or environ.get("AWS_DEFAULT_REGION")

        self.__IDP = client(
            "cognito-idp",
            region_name=self.config["region_name"],
            config=BotoConfig(signature_version=UNSIGNED)
        )

        self.__IDENTITY = client("cognito-identity", region_name=self.config["region_name"])

        if self.config["auth_flow"] == "classic":
            self.__STS = client("sts")
            self.__COGNITO_IDP = client("cognito-idp", region_name=self.config["region_name"])

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
                method=self.__METHOD
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

        auth = self.__IDP.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=self.config.get("metadata"),
        )

        response = srp.process_challenge(auth["ChallengeParameters"])

        auth = self.__IDP.respond_to_auth_challenge(
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
        auth = self.__IDP.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=AUTH_PARAMETERS,
            ClientId=self.config["app_id"],
            ClientMetadata=self.config.get("metadata")
        )["AuthenticationResult"]

        self.auth = auth
        return auth

    def _refresh_auth(self) -> dict:
        LOGGER.debug("Refreshing auth")
        AUTH_PARAMETERS = {"REFRESH_TOKEN": self.token_cache.tokens["refresh_token"]}
        try:
            auth = self.__IDP.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=AUTH_PARAMETERS,
                ClientId=self.config["app_id"],
                ClientMetadata=self.config.get("metadata"),
            )["AuthenticationResult"]

            auth["RefreshToken"] = self.token_cache.tokens["refresh_token"]
            return auth
        except self.__IDP.exceptions.NotAuthorizedException as e:
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
                identityId = self.__IDENTITY.get_id(
                    IdentityPoolId=self.config["identity_pool_id"],
                    Logins={f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": id_token}
                )["IdentityId"]

            except self.__IDENTITY.exceptions.NotAuthorizedException as e:
                LOGGER.info(f"LOGIN ERROR: {e}")
                self.token_cache.tokens["id_token"] = None
                fetch()

            if self.config["auth_flow"] == "classic":
                LOGGER.debug("Using classic auth flow....")
                token = self.__IDENTITY.get_open_id_token(
                    IdentityId=identityId,
                    Logins={
                        f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": self.token_cache.tokens["id_token"]
                    }
                )["Token"]

                if self.config.get("role_session_name") is None:
                    attributes = self.__COGNITO_IDP.get_user(
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

                credentials = self.__STS.assume_role_with_web_identity(**opts)
                credentials["Credentials"]["SecretKey"] = credentials["Credentials"]["SecretAccessKey"]
            else:
                opts = {
                    "IdentityId": identityId,
                    "Logins": {f"""cognito-idp.{self.config["region_name"]}.amazonaws.com/{self.config["user_pool_id"]}""": id_token}
                }
                if self.config.get("role_arn"):
                    opts["CustomRoleArn"] = self.config.get("role_arn")

                credentials = self.__IDENTITY.get_credentials_for_identity(**opts)

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
