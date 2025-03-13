# coding:utf-8

from typing import Optional
from uuid import uuid4

from xkits import CacheTimeUnit
from xkits import ItemPool

from xpw.password import Pass


class SessionPool(ItemPool[str, str]):
    """Session pool"""

    def __init__(self, lifetime: CacheTimeUnit = 3600.0):  # 1 hour
        super().__init__(lifetime=lifetime)

    def new(self, lifetime: Optional[CacheTimeUnit] = None) -> str:
        session_id: str = str(uuid4())
        secret_key: str = Pass.random_generate(64).value
        self.put(index=session_id, value=secret_key, lifetime=lifetime)
        return session_id
