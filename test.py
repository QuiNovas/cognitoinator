#!/usr/bin/env python3.8
import boto3
from cognito_assume_role import user_password

c = boto3.client("s3")
while True:
    res = c.list_buckets()
    print(res['ResponseMetadata']['RequestId'])
