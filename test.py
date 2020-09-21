#!/usr/bin/env python3.8
from cognito_assume_role import Session, TokenFetcher

# session = Session(token_cache="/Users/mathew/tokens")
# s3 = session.client("s3")
# print(s3.list_buckets())
# tokens = session.tokens
# print(tokens)

fetcher = TokenFetcher()
print(fetcher.fetch())
