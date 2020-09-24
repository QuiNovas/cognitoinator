from os import environ, path, access, W_OK
from pathlib import Path
from io import StringIO
from boto3.session import Session as botosession
from botocore.configloader import load_config
from botocore.session import get_session
from .providers import CognitoIdentity, TokenFetcher, TokenCache

COGNITO_DEFAULT_SESSION = None


def _get_default_session(**kwargs):
    global COGNITO_DEFAULT_SESSION
    if COGNITO_DEFAULT_SESSION is None:
        COGNITO_DEFAULT_SESSION = Session(**kwargs)
    return COGNITO_DEFAULT_SESSION


def Session(**kwargs):

    args_to_remove = [
        "cognito_profile",
        "cognito_config",
        "cognito_credentials_file",
        "auth_type",
        "token_cache"
    ]

    # Resolve profile through possible config file locations and then config
    if kwargs.get("cognito_profile") and kwargs.get("cognito_config"): raise ValueError("kwargs cognito_profile and cognito_config are mutually exclusive")

    if profile_name := kwargs.get("cognito_profile"):
        config = get_profile(profile_name, kwargs.get("cognito_credentials_file"))
    elif kwargs.get("cognito_config"):
        config = kwargs["cognito_config"]
    else:
        config = {}

    auth_type = kwargs.get("auth_type") or config.get("auth_type") or "user_srp"
    if auth_type not in ("user_passwword", "user_srp"): raise ValueError("auth_type must be one of user_password or user_srp")

    # If token_cache file is provided we will use it, otherwise we will use a StringIO object
    if token_cache := kwargs.get("token_cache"):
        if not path.isfile(token_cache): raise FileNotFoundError(f"File {token_cache} specified as a token cache does not exist.")
        if not access(token_cache, W_OK): raise OSError(f"File {token_cache} is not writable.")
        token_cache = TokenCache(token_cache)
    else:
        cache_io = StringIO()
        token_cache = TokenCache(cache_io)

    # Create our credential provider
    auth_client = CognitoIdentity(
        auth_type,
        config=config,
        token_cache=token_cache
    )

    bc_session = get_session()

    # Clean our own kwargs out so that we can pass the remainder to boto.
    session_args = {k: kwargs[k] for k in kwargs if k not in args_to_remove}
    session_args["botocore_session"] = bc_session

    session = botosession(**session_args)

    # Now we set the session so when we get the token's getter properties we
    # retreive from the same cache that the provider is using.
    session.token_cache = token_cache

    # Now we can fire a call to refresh auth tokens if we need to
    session.refresh_auth = auth_client.refresh_auth

    # Insert our credential provider at the top of the chain
    cognito_provider = bc_session.get_component('credential_provider')
    cognito_provider.insert_before('env', auth_client)

    # If we don't pre-load then we won't have access to the tokens until after either client() or resource() is called
    auth_client.load()
    return session


def get_profile(name, credentials_file):
    credentials_file = credentials_file or environ.get("COGNITO_CREDENTIALS_FILE") or f"{Path.home()}/.aws/cognito_credentials"
    if not path.isfile(credentials_file): raise Exception("Cannot find cognito_credentials_file")
    profiles = parse_config(credentials_file).get("profiles", {})
    if name not in profiles:
        raise Exception(f"Specified cognito_profile does not exist in {credentials_file}")
    return profiles[name]


def client(*args, **kwargs):
    session_opts = {
        "auth_type": kwargs.get("auth_type"),
        "cognito_profile": kwargs.get("cognito_profile"),
        "cognito_credentials_file": kwargs.get("cognito_credentials_file")
    }
    client_opts = {x: kwargs[x] for x in kwargs if x not in session_opts}
    return _get_default_session(**session_opts).client(*args, **client_opts)


def resource(*args, **kwargs):
    session_opts = {
        "auth_type": kwargs.get("auth_type"),
        "cognito_profile": kwargs.get("cognito_profile"),
        "cognito_credentials_file": kwargs.get("cognito_credentials_file")
    }
    resource_opts = {x: kwargs[x] for x in kwargs if x not in session_opts}
    return _get_default_session(**session_opts).resource(*args, **resource_opts)


# Patch boto3.session.Session so we can get our Cognito tokens from our session later
def parse_config(filename):
    config = load_config(filename)
    return config


@property
def id_token(self):
    return self.token_cache.tokens.get("id_token")


@property
def access_token(self):
    return self.token_cache.tokens.get("access_token")


@property
def refresh_token(self):
    return self.token_cache.tokens.get("refresh_token")


@property
def token_expires(self):
    return self.token_cache.tokens.get("token_expires")


@property
def cognito_tokens(self):
    return self.token_cache.tokens


botosession.id_token = id_token
botosession.access_token = access_token
botosession.refresh_token = refresh_token
botosession.token_expires = token_expires
botosession.tokens = cognito_tokens
botosession.token_cache = None
