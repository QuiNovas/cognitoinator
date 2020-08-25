from os import environ
from .common import CognitoAssumeRole, is_cognito, patch_boto

CognitoAssumeRole._login = CognitoAssumeRole._srp_auth

auth = CognitoAssumeRole()

patch_boto(auth)
if is_cognito():
    environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = " "  # Nuance of boto3. It is intentional
