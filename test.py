
from cognito_assume_role import TokenFetcher

s = TokenFetcher()
# Strings shortened for brevity
print(s.id_token[-10:-1])
print(s.access_token[-10:-1])
print(s.refresh_token[-10:-1])
print(s.expires)

"""
Results in:
  6xAb_vMKv
  4Ruc_TB_h
  m3Htft_Op
  2020-09-19T05:16:31
"""
