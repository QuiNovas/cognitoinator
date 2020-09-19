from os import environ, path
from pathlib import Path
from boto3.session import Session as botosession
from botocore.configloader import load_config
from botocore.session import get_session
from .providers import CognitoIdentity, TokenFetcher


def Session(**kwargs):
    assert not (kwargs.get("cognito_profile") and kwargs.get("cognito_config")), "kwargs cognito_profile and cognito_config are mutually exclusive"
    if profile_name := kwargs.get("cognito_profile"):
        config = get_profile(profile_name, kwargs.get("cognito_credentials_file"))
        del kwargs["cognito_profile"]
        if "cognito_credentials_file" in kwargs: del kwargs["cognito_credentials_file"]
    elif kwargs.get("cognito_config"):
        config = kwargs["cognito_config"]
        del kwargs["cognito_config"]
    else:
        config = {}

    auth_type = kwargs.get("auth_type") or config.get("auth_type") or "user_srp"
    assert auth_type in ("user_passwword", "user_srp"), "auth_type must be one of user_password or user_srp"

    auth_client = CognitoIdentity(auth_type, config=config)
    bc_session = get_session()
    session = botosession(botocore_session=bc_session)
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


def parse_config(filename):
    config = load_config(filename)
    return config
