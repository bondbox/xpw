# coding:utf-8

from abc import ABC
from abc import abstractmethod
from typing import Optional

from .configure import Argon2Config
from .configure import BasicConfig
from .configure import CONFIG_DATA_TYPE
from .configure import DEFAULT_CONFIG_FILE
from .configure import LdapConfig
from .password import Argon2Hasher


class BasicAuth(ABC):
    def __init__(self, config: BasicConfig):
        self.__config: BasicConfig = config

    @property
    def config(self) -> BasicConfig:
        return self.__config

    @abstractmethod
    def verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        pass


class Argon2Auth(BasicAuth):
    def __init__(self, datas: CONFIG_DATA_TYPE):
        super().__init__(Argon2Config(datas))

    @property
    def config(self) -> Argon2Config:
        config = super().config
        if not isinstance(config, Argon2Config):
            raise TypeError("config type error")
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
        config = super().config
        if not isinstance(config, LdapConfig):
            raise TypeError("config type error")
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

    def __init__(self):
        pass

    @classmethod
    def from_file(cls, path: str = DEFAULT_CONFIG_FILE) -> BasicAuth:
        config: CONFIG_DATA_TYPE = BasicConfig.loadf(path)
        basic: CONFIG_DATA_TYPE = config.get("basic", {})
        return cls.METHODS[basic.get("auth_method", Argon2Config.TYPE)](config)
