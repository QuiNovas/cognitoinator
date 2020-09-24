#!/usr/bin/env python3.8
from cognito_assume_role import Session, TokenFetcher
from time import sleep


session = Session()
s3 = session.client("s3")

s3.list_buckets()

old_token = None
new_token = None
old_expires = None
new_expires = None
print(session.tokens)
n = 1
while True:
    s3.list_buckets()
    new_expires = session.tokens["token_expires"]
    new_token = session.tokens["id_token"]
    if old_expires != new_expires and old_expires is not None:
        print("Expiration has CHANGED!!!!!!!!!")
        print(new_expires)
    else:
        print("Expiration unchanged: " + new_expires)

    if old_token != new_token and old_token is not None:
        print("TOKEN HAS CHANGED!!!!!!!!!!!!!!!")
        print(new_token[-20:-1])
    else:
        print("Token unchanged: " + new_token[-20:-1] + ", Iteration: " + str(n))
    old_token = new_token
    old_expires = new_expires
    n += 1
    sleep(30)

# fetcher = TokenFetcher()
# print(fetcher.fetch())
