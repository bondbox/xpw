# coding:utf-8

from typing import Optional
from uuid import uuid4

from xkits_lib.cache import CacheExpired
from xkits_lib.cache import CacheItem
from xkits_lib.cache import CacheMiss
from xkits_lib.cache import ItemPool
from xkits_lib.unit import TimeUnit

from xpw.password import Pass
from xpw.password import Secret


class SessionKeys(ItemPool[str, Optional[str]]):
    """Session Secret Pool"""

    def __init__(self, secret_key: Optional[str] = None, lifetime: TimeUnit = 3600.0):  # noqa:E501
        self.__secret: Secret = Secret(secret_key or Pass.random_generate(64).value)  # noqa:E501
        super().__init__(lifetime=lifetime)

    @property
    def secret(self) -> Secret:
        return self.__secret

    def search(self, s: Optional[str] = None) -> CacheItem[str, Optional[str]]:  # noqa:E501
        session_id: str = s or str(uuid4())
        if session_id not in self:
            self.put(session_id, None)
        return self.get(session_id)

    def verify(self, session_id: str, secret_key: Optional[str] = None) -> bool:  # noqa:E501
        try:
            token: str = secret_key or self.secret.key
            return self[session_id].data == token
        except (CacheExpired, CacheMiss):
            return False

    def sign_in(self, session_id: str, secret_key: Optional[str] = None) -> str:  # noqa:E501
        self.search(session_id).update(token := secret_key or self.secret.key)
        return token

    def sign_out(self, session_id: str) -> None:
        self.delete(session_id)
