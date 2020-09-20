#!/usr/bin/env python3.8
from cognito_assume_role import Session

session = Session()
s3 = session.client("s3")
s3.list_buckets()

print(session.token_expires)
