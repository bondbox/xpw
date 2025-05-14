# coding:utf-8

from typing import Dict
from typing import Optional

from xpw.configure import Argon2Config
from xpw.configure import BasicConfig
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

    @property
    def tokens(self) -> Dict[str, str]:
        return self.config.datas[self.SECTION]

    def verify_token(self, code: str) -> Optional[str]:
        return self.tokens.get(code)

    def delete_token(self, code: str) -> None:
        if code in (tokens := self.tokens):
            del tokens[code]
        assert code not in self.tokens
        self.config.dumpf()

    def update_token(self, code: str, user: str = "") -> None:
        self.tokens[code] = user
        self.config.dumpf()

    def generate_token(self, user: str = "") -> str:
        from xpw.password import Pass  # pylint:disable=import-outside-toplevel

        secret: Pass = Pass.random_generate(64, Pass.CharacterSet.ALPHANUMERIC)
        self.update_token(code := secret.value, user)
        return code

    def verify_password(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        raise NotImplementedError()

    def change_password(self, username: str, old_password: str, new_password: str) -> Optional[str]:  # noqa:E501
        """change user password"""
        raise NotImplementedError()

    def create_user(self, username: str, password: str) -> Optional[str]:
        """create new user"""
        raise NotImplementedError()

    def delete_user(self, username: str, password: str) -> bool:
        """delete user"""
        raise NotImplementedError()

    def verify(self, k: str, v: Optional[str] = None) -> Optional[str]:
        if k == "":  # no available username, verify token
            assert isinstance(v, str)
            return self.verify_token(v)

        return self.verify_password(k, v)


class Argon2Auth(TokenAuth):
    def __init__(self, config: BasicConfig):
        super().__init__(Argon2Config(config))

    @property
    def config(self) -> Argon2Config:
        assert isinstance(config := super().config, Argon2Config)
        return config

    def verify_password(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
        try:
            hasher: Argon2Hasher = self.config[username]
            if hasher.verify(password or input("password: ")):
                return username
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None

    def change_password(self, username: str, old_password: str, new_password: str) -> Optional[str]:  # noqa:E501
        self.config.change(username, old_password, new_password)
        return self.verify_password(username, new_password)

    def create_user(self, username: str, password: str) -> Optional[str]:
        self.config.create(username, password)
        return self.verify_password(username, password)

    def delete_user(self, username: str, password: str) -> bool:
        return self.config.delete(username, password)


class LdapAuth(TokenAuth):
    def __init__(self, config: BasicConfig):
        super().__init__(LdapConfig(config))

    @property
    def config(self) -> LdapConfig:
        assert isinstance(config := super().config, LdapConfig)
        return config

    def verify_password(self, username: str, password: Optional[str] = None) -> Optional[str]:  # noqa:E501
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

    def change_password(self, username: str, old_password: str, new_password: str) -> Optional[str]:  # noqa:E501
        raise NotImplementedError()

    def create_user(self, username: str, password: str) -> Optional[str]:
        raise NotImplementedError()

    def delete_user(self, username: str, password: str) -> bool:
        raise NotImplementedError()


class AuthInit():  # pylint: disable=too-few-public-methods
    METHODS = {
        Argon2Config.SECTION: Argon2Auth,
        LdapConfig.SECTION: LdapAuth,
    }

    @classmethod
    def from_file(cls, path: str = DEFAULT_CONFIG_FILE) -> TokenAuth:
        config: BasicConfig = BasicConfig.loadf(path)
        method: str = config.datas.get("auth_method", Argon2Config.SECTION)
        return cls.METHODS[method](config)
