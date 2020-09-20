from os import environ, path
from pathlib import Path
from uuid import uuid4
from boto3.session import Session as botosession
from botocore.configloader import load_config
from botocore.session import get_session
from .providers import CognitoIdentity, JSONFileCache


def Session(**kwargs):
    args_to_remove = [
        "cognito_profile",
        "cognito_config",
        "cognito_credentials_file",
        "auth_type",
        "cache_credentials",
        "credential_cache_dir"
    ]

    # Resolve profile through possible config file locations and then config
    if kwargs.get("cognito_profile") and kwargs.get("cognito_config"): raise ValueError("kwargs cognito_profile and cognito_config are mutually exclusive")
    if kwargs.get("cache_credentials") not in (True, False, None): raise ValueError("Option cache_credentials must be a boolean")
    if kwargs.get("cache_credentials") == False and kwargs.get("credential_cache_dir"): raise ValueError("Cannot set credential_cache_dir if cache_credentials is False")

    if profile_name := kwargs.get("cognito_profile"):
        config = get_profile(profile_name, kwargs.get("cognito_credentials_file"))
    elif kwargs.get("cognito_config"):
        config = kwargs["cognito_config"]
    else:
        config = {}

    auth_type = kwargs.get("auth_type") or config.get("auth_type") or "user_srp"
    if auth_type not in ("user_passwword", "user_srp"): raise ValueError("auth_type must be one of user_password or user_srp")

    # So we can cache our tokens in CognitoIdentity to retreive from the session
    # If cache_credentials isn't set or is True we will cache credentials otherwise not
    cache_id = str(uuid4()) if kwargs.get("cache_credentials") in (True, None) else None
    cache_dir = kwargs.get("credential_cache_dir")

    # Create our credential provider
    auth_client = CognitoIdentity(
        auth_type,
        config=config,
        cache_id=cache_id,
        cache_dir=cache_dir
    )
    bc_session = get_session()

    # Clean our own kwargs out so that we can pass the remainder to boto.
    session_args = {k: kwargs[k] for k in kwargs if k not in args_to_remove}
    session_args["botocore_session"] = bc_session
    session = botosession(**session_args)

    # Now we set the cache_id on the session so when we get the token's getter properties we
    # retreive from the same cache that the provider is using.
    session.cache_id = cache_id

    # Insert our credential provider at the top of the chain
    cognito_provider = bc_session.get_component('credential_provider')
    cognito_provider.insert_before('env', auth_client)

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
    cognito_session = Session(**session_opts)
    return cognito_session.client(*args, **client_opts)


def resource(*args, **kwargs):
    session_opts = {
        "auth_type": kwargs.get("auth_type"),
        "cognito_profile": kwargs.get("cognito_profile"),
        "cognito_credentials_file": kwargs.get("cognito_credentials_file")
    }
    resource_opts = {x: kwargs[x] for x in kwargs if x not in session_opts}
    cognito_session = Session(**session_opts)
    return cognito_session.resource(*args, **resource_opts)


# Monkey patch boto3.session.Session so we can get our Cognito tokens from our session later
def parse_config(filename):
    config = load_config(filename)
    return config


@property
def id_token(self):
    return self.cognito_tokens.get("id_token")


@property
def access_token(self):
    return self.cognito_tokens.get("access_token")


@property
def refresh_token(self):
    return self.cognito_tokens.get("refresh_token")


@property
def token_expires(self):
    return self.cognito_tokens.get("token_expires")


@property
def cognito_tokens(self):
    try:
        item = self.token_cache.__getitem__(self.cache_id)
    except KeyError:
        item = {}
    return item


botosession.id_token = id_token
botosession.access_token = access_token
botosession.refresh_token = refresh_token
botosession.token_expires = token_expires
botosession.cache_id = str()
botosession.cognito_tokens = cognito_tokens
botosession.token_cache = JSONFileCache()
