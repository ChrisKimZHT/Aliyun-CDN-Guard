from __future__ import annotations

from alibabacloud_credentials.client import Client as CredentialClient
from aliyun.log.credentials import Credentials, CredentialsProvider


class SlsCredentialProvider(CredentialsProvider):
    """Bridge Alibaba Cloud's default credential chain to the SLS SDK."""

    def __init__(self, client: CredentialClient):
        self.client = client

    def get_credentials(self) -> Credentials:
        credential = self.client.get_credential()
        return Credentials(
            credential.access_key_id,
            credential.access_key_secret,
            credential.security_token,
        )
