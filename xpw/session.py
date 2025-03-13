# coding:utf-8

from typing import Optional
from uuid import uuid4

from xkits import CacheExpired
from xkits import CacheItem
from xkits import CacheMiss
from xkits import CacheTimeUnit
from xkits import ItemPool

from xpw.password import Pass


class SessionPool(ItemPool[str, Optional[str]]):
    """Session pool"""

    def __init__(self, secret_key: Optional[str] = None, lifetime: CacheTimeUnit = 3600.0):  # noqa:E501
        self.__secret_key: str = secret_key or Pass.random_generate(64).value
        super().__init__(lifetime=lifetime)

    @property
    def secret_key(self) -> str:
        return self.__secret_key

    def search(self, id: Optional[str] = None) -> CacheItem[str, Optional[str]]:  # noqa:E501
        session_id: str = id or str(uuid4())
        if session_id not in self:
            self.put(session_id, None)
        return self.get(session_id)

    def verify(self, id: Optional[str] = None) -> bool:
        try:
            return isinstance(id, str) and self[id].data == self.secret_key
        except (CacheExpired, CacheMiss):
            return False

    def sign_in(self, session_id: str, secret_key: Optional[str] = None) -> bool:  # noqa:E501
        self.search(session_id).update(secret_key or self.secret_key)
        return session_id in self

    def sign_out(self, session_id: str) -> bool:
        self.delete(session_id)
        return session_id not in self
