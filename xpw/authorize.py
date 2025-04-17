# coding:utf-8

from typing import Optional

from xpw.attribute import __project__
from xpw.configure import Argon2Config
from xpw.configure import BasicConfig
from xpw.configure import CONFIG_DATA_TYPE
from xpw.configure import DEFAULT_CONFIG_FILE
from xpw.configure import LdapConfig
from xpw.password import Argon2Hasher


class TokenAuth():
    SECTION = "tokens"

    def __init__(self, config: BasicConfig):
        config.datas.setdefault(self.SECTION, {})
        assert isinstance(config.datas[self.SECTION], dict)
        self.__config: BasicConfig = config

    @property
    def config(self) -> BasicConfig:
        return self.__config

    def delete_token(self, token: str) -> None:
        if token in self.config.datas[self.SECTION]:
            del self.config.datas[self.SECTION][token]
        assert token not in self.config.datas[self.SECTION]

    def update_token(self, token: str, note: Optional[str] = None) -> None:
        self.config.datas[self.SECTION][token] = note or __project__

    def generate_token(self, note: Optional[str] = None) -> str:
        from xpw.password import Pass  # pylint:disable=import-outside-toplevel

        secret: Pass = Pass.random_generate(64, Pass.CharacterSet.ALPHANUMERIC)
        self.update_token(token := secret.value, note)
        return token

    def password_verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        raise NotImplementedError()

    def token_verify(self, token: str) -> Optional[str]:
        return self.config.datas[self.SECTION].get(token)

    def verify(self, k: str, v: Optional[str] = None) -> Optional[str]:
        if k == "":
            assert isinstance(v, str)
            return self.token_verify(v)

        return self.password_verify(k, v)


class Argon2Auth(TokenAuth):
    def __init__(self, datas: CONFIG_DATA_TYPE):
        super().__init__(Argon2Config(datas))

    @property
    def config(self) -> Argon2Config:
        assert isinstance(config := super().config, Argon2Config)
        return config

    def password_verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        try:
            hasher: Argon2Hasher = self.config[username]
            if hasher.verify(password or input("password: ")):
                return username
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None


class LdapAuth(TokenAuth):
    def __init__(self, datas: CONFIG_DATA_TYPE):
        super().__init__(LdapConfig(datas))

    @property
    def config(self) -> LdapConfig:
        assert isinstance(config := super().config, LdapConfig)
        return config

    def password_verify(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
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
        Argon2Config.SECTION: Argon2Auth,
        LdapConfig.SECTION: LdapAuth,
    }

    @classmethod
    def from_file(cls, path: str = DEFAULT_CONFIG_FILE) -> TokenAuth:
        config: CONFIG_DATA_TYPE = BasicConfig.loadf(path)
        method: str = config.get("auth_method", Argon2Config.SECTION)
        return cls.METHODS[method](config)
