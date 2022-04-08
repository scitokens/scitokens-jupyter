"""
Types and abstractions for working with tokens.
"""

import dataclasses
import time
from typing import Dict, Optional, Union

__all__ = [
    "OAuth2Token",
    "OAuth2TokenDB",
    #
    "InMemoryOAuth2TokenDB",
]


@dataclasses.dataclass
class OAuth2Token:
    """
    Represents the data returned by an OAuth2 token endpoint.
    """

    ## Required fields in the OAuth2 specification.
    access_token: str
    token_type: str

    ## Not in the OAuth2 specification, but useful information to record.
    updated_at: Union[int, float]  # seconds since the epoch

    ## Optional fields in the OAuth2 specification.
    expires_in: Optional[int] = None  # should be relative to `updated_at`
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class OAuth2TokenDB:
    """
    Defines an interface for a database storing OAuth2 tokens.

    The intent is for tokens to be stored as they were originally issued.
    """

    def _put_into_db(self, uid: str, token: OAuth2Token) -> None:
        """
        Low-level operation for writing a token into storage.
        """
        raise NotImplementedError

    def _get_from_db(self, uid: str) -> Optional[OAuth2Token]:
        """
        Low-level operation for reading a token from storage.
        """
        raise NotImplementedError

    def put(
        self,
        uid: str,
        *,
        access_token: str,
        token_type: str,
        expires_in: Optional[int] = None,
        refresh_token: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> None:
        """
        Writes an OAuth2 token into the database.
        """

        token = OAuth2Token(
            access_token=access_token,
            token_type=token_type,
            updated_at=time.time(),
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=scope,
        )

        self._put_into_db(uid, token)

    def get(self, uid: str) -> Optional[OAuth2Token]:
        """
        Reads an OAuth2 token from the database.
        """

        token = self._get_from_db(uid)

        # Return a copy of the token object in case the database
        # is holding a reference to it. The token object is mutable
        # and thus might be modified by the caller.

        if token:
            token = dataclasses.replace(token)

        return token


class InMemoryOAuth2TokenDB(OAuth2TokenDB):
    """
    Uses a built-in `dict` to store tokens in memory.
    """

    def __init__(self):
        self._db: Dict[str, OAuth2Token] = {}

    def _put_into_db(self, uid: str, token: OAuth2Token) -> None:
        self._db[uid] = token

    def _get_from_db(self, uid: str) -> Optional[OAuth2Token]:
        return self._db.get(uid)
