# coding:utf-8

from typing import Optional

from xkits_lib.cache import CacheExpired
from xkits_lib.cache import CacheItem
from xkits_lib.cache import CacheMiss
from xkits_lib.cache import ItemPool
from xkits_lib.unit import TimeUnit

from xpw.password import Pass
from xpw.password import Secret


class SessionID():
    def __init__(self, user_agent: str, session_id: Optional[str] = None):
        self.__session_id: str = session_id or self.generate()
        self.__user_agent: str = user_agent

    @property
    def number(self) -> str:
        return self.__session_id

    @property
    def detail(self) -> str:
        return self.__user_agent

    @property
    def digest(self) -> str:
        return self.encode(self.detail)

    def verify(self, user_agent) -> bool:
        return self.digest == self.encode(user_agent)

    @classmethod
    def encode(cls, user_agent: str) -> str:
        from hashlib import md5  # pylint: disable=import-outside-toplevel

        return md5(user_agent.encode("utf-8")).hexdigest()

    @classmethod
    def generate(cls) -> str:
        """Generate a 32-bit hexadecimal random session_id"""
        return Pass.random_generate(32, "0123456789abcdef").value


class SessionKeys(ItemPool[str, Optional[str]]):
    """Session Secret Pool"""

    def __init__(self, secret_key: Optional[str] = None, lifetime: TimeUnit = 3600.0):  # noqa:E501
        self.__secret: Secret = Secret(secret_key or Pass.random_generate(64).value)  # noqa:E501
        super().__init__(lifetime=lifetime)

    @property
    def secret(self) -> Secret:
        return self.__secret

    def search(self, s: Optional[str] = None) -> CacheItem[str, Optional[str]]:  # noqa:E501
        session_id: str = s or SessionID.generate()
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
