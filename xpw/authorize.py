# coding:utf-8

from typing import Dict
from typing import Optional
from typing import Tuple

from xpw.configure import Argon2Config
from xpw.configure import BasicConfig
from xpw.configure import DEFAULT_CONFIG_FILE
from xpw.configure import LdapConfig
from xpw.password import Argon2Hasher


class Token():
    def __init__(self, name: str, note: str, hash: str, user: str):  # noqa:E501, pylint:disable=redefined-builtin
        assert isinstance(name, str) and len(name) > 0
        self.__name: str = name
        self.__note: str = note
        self.__hash: str = hash
        self.__user: str = user

    def __str__(self) -> str:
        return f"{__class__.__name__}({self.name}, {self.user}, {self.note})"

    @property
    def name(self) -> str:
        return self.__name

    @property
    def note(self) -> str:
        return self.__note

    @property
    def hash(self) -> str:
        return self.__hash

    @property
    def user(self) -> str:
        return self.__user

    def dump(self) -> Tuple[str, str, str]:
        return (self.note, self.hash, self.user)

    def renew(self) -> "Token":
        return Token(name=self.name, note=self.note, hash=self.generate(), user=self.user)  # noqa:E501

    @classmethod
    def create(cls, note: str = "", user: str = "") -> "Token":
        from uuid import uuid4  # pylint:disable=import-outside-toplevel

        return cls(name=str(uuid4()), note=note, hash=cls.generate(), user=user)  # noqa:E501

    @classmethod
    def generate(cls) -> str:
        from xpw.password import Pass  # pylint:disable=import-outside-toplevel

        return Pass.random_generate(64, Pass.CharacterSet.ALPHANUMERIC).value


class TokenAuth():
    SECTION = "tokens"

    def __init__(self, config: BasicConfig):
        config.datas.setdefault(self.SECTION, {})
        tokens: Dict[str, Tuple[str, str, str]] = config.datas[self.SECTION]
        assert isinstance(tokens, dict), f"unexpected type: '{type(tokens)}'"
        self.__tokens: Dict[str, Token] = {v[1]: Token(k, *v) for k, v in tokens.items()}  # noqa:E501
        self.__config: BasicConfig = config

    @property
    def config(self) -> BasicConfig:
        return self.__config

    @property
    def tokens(self) -> Dict[str, Token]:
        return self.__tokens

    def verify_token(self, hash: str) -> Optional[str]:  # pylint:disable=W0622
        return token.user if (token := self.tokens.get(hash)) else None

    def delete_token(self, hash: str) -> None:  # pylint:disable=W0622
        if token := self.tokens.get(hash):
            del self.config.datas[self.SECTION][token.name]
            del self.tokens[hash]
            self.config.dumpf()
        assert hash not in self.tokens

    def update_token(self, hash: str) -> Optional[str]:  # pylint:disable=W0622
        if token := self.tokens.get(hash):
            tokens: Dict[str, Tuple[str, str, str]] = self.config.datas[self.SECTION]  # noqa:E501
            tokens[token.name] = (new := token.renew()).dump()
            del self.tokens[token.hash]  # delete old token
            self.tokens.setdefault(new.hash, new)
            self.config.dumpf()
            return new.hash
        return None

    def generate_token(self, note: str = "", user: str = "") -> str:
        tokens: Dict[str, Tuple[str, str, str]] = self.config.datas[self.SECTION]  # noqa:E501
        tokens.setdefault((token := Token.create(note, user)).name, token.dump())  # noqa:E501
        self.tokens.setdefault(token.hash, token)
        self.config.dumpf()
        return token.hash

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
