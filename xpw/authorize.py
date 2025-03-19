# coding:utf-8

from abc import ABC
from abc import abstractmethod
from typing import Optional

from xpw.configure import Argon2Config
from xpw.configure import BasicConfig
from xpw.configure import CONFIG_DATA_TYPE
from xpw.configure import DEFAULT_CONFIG_FILE
from xpw.configure import LdapConfig
from xpw.password import Argon2Hasher


class BasicAuth(ABC):
    def __init__(self, config: BasicConfig):
        self.__config: BasicConfig = config

    @property
    def config(self) -> BasicConfig:
        return self.__config

    @abstractmethod
    def verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        raise NotImplementedError()


class Argon2Auth(BasicAuth):
    def __init__(self, datas: CONFIG_DATA_TYPE):
        super().__init__(Argon2Config(datas))

    @property
    def config(self) -> Argon2Config:
        assert isinstance(config := super().config, Argon2Config)
        return config

    def verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        try:
            hasher: Argon2Hasher = self.config[username]
            if hasher.verify(password or input("password: ")):
                return username
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None


class LdapAuth(BasicAuth):
    def __init__(self, datas: CONFIG_DATA_TYPE):
        super().__init__(LdapConfig(datas))

    @property
    def config(self) -> LdapConfig:
        assert isinstance(config := super().config, LdapConfig)
        return config

    def verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        try:
            config: LdapConfig = self.config
            entry = config.client.signed(config.base_dn, config.filter,
                                         config.attributes, username,
                                         password or input("password: "))
            if entry:
                return entry.entry_dn
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None


class AuthInit():  # pylint: disable=too-few-public-methods
    METHODS = {
        Argon2Config.TYPE: Argon2Auth,
        LdapConfig.TYPE: LdapAuth,
    }

    @classmethod
    def from_file(cls, path: str = DEFAULT_CONFIG_FILE) -> BasicAuth:
        config: CONFIG_DATA_TYPE = BasicConfig.loadf(path)
        method: str = config.get("auth_method", Argon2Config.TYPE)
        return cls.METHODS[method](config)
