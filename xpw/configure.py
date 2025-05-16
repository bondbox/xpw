# coding:utf-8

from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from xkits_file import SafeRead
from xkits_file import SafeWrite

from xpw.ldapauth import LdapClient
from xpw.ldapauth import LdapInit
from xpw.password import Argon2Hasher
from xpw.password import Pass

CONFIG_DATA_TYPE = Dict[str, Any]
DEFAULT_CONFIG_FILE = "xpwauth"


class BasicConfig():

    def __init__(self, path: str, datas: CONFIG_DATA_TYPE):
        self.__datas: CONFIG_DATA_TYPE = datas
        self.__path: str = path

        if "secret" not in self.datas:
            secret_key: str = Pass.random_generate(64).value
            self.datas.setdefault("secret", secret_key)
            self.dumpf()

    @property
    def path(self) -> str:
        return self.__path

    @property
    def datas(self) -> CONFIG_DATA_TYPE:
        return self.__datas

    @property
    def secret_key(self) -> str:
        return self.datas["secret"]

    @property
    def lifetime(self) -> int:
        return self.datas.get("lifetime", 0)

    @classmethod
    def loadf(cls, path: str = DEFAULT_CONFIG_FILE) -> "BasicConfig":
        """load config from toml file"""
        from toml import loads  # pylint: disable=import-outside-toplevel

        with SafeRead(path, encoding="utf-8") as rhdl:
            return cls(path=path, datas=loads(rhdl.read()))

    def dumps(self) -> str:
        """dump config to toml string"""
        from toml import dumps  # pylint: disable=import-outside-toplevel

        return dumps(self.datas)

    def dumpf(self, path: Optional[str] = None) -> None:
        """dump config to toml file"""
        with SafeWrite(path or self.path, encoding="utf-8", truncate=True) as whdl:  # noqa:E501
            whdl.write(self.dumps())


class Argon2Config(BasicConfig):
    SECTION = "argon2"

    def __init__(self, config: BasicConfig):
        config.datas.setdefault(self.SECTION, {})
        config.datas.setdefault("users", {})
        super().__init__(config.path, config.datas)

    def __contains__(self, user: str) -> bool:
        return user in self.datas["users"]

    def __getitem__(self, user: str) -> Argon2Hasher:
        return self.generate(self.datas["users"][user])

    @property
    def time_cost(self) -> int:
        return self.datas[self.SECTION].get("time_cost", Argon2Hasher.DEFAULT_TIME_COST)  # noqa:E501

    @property
    def memory_cost(self) -> int:
        return self.datas[self.SECTION].get("memory_cost", Argon2Hasher.DEFAULT_MEMORY_COST)  # noqa:E501

    @property
    def parallelism(self) -> int:
        return self.datas[self.SECTION].get("parallelism", Argon2Hasher.DEFAULT_PARALLELISM)  # noqa:E501

    @property
    def hash_len(self) -> int:
        return self.datas[self.SECTION].get("hash_length", Argon2Hasher.DEFAULT_HASH_LENGTH)  # noqa:E501

    @property
    def salt_len(self) -> int:
        return self.datas[self.SECTION].get("salt_length", Argon2Hasher.DEFAULT_SALT_LENGTH)  # noqa:E501

    @property
    def salt(self) -> str:
        return self.datas[self.SECTION].get("salt", None)

    def generate(self, password: str) -> Argon2Hasher:
        return Argon2Hasher(password) if password.startswith("$") else self.encode(password)  # noqa:E501

    def encode(self, password: str) -> Argon2Hasher:
        return Argon2Hasher.hash(password=password, salt=self.salt,
                                 time_cost=self.time_cost,
                                 memory_cost=self.memory_cost,
                                 parallelism=self.parallelism,
                                 hash_len=self.hash_len,
                                 salt_len=self.salt_len)

    def change(self, username: str, old_password: str, new_password: str) -> bool:  # noqa:E501
        assert isinstance(users := self.datas["users"], dict)
        if username not in users:
            raise ValueError(f"user '{username}' not exists")

        if not self[username].verify(old_password):
            raise ValueError("password error")

        users[username] = self.encode(new_password).hashed
        self.dumpf()

        return self[username].verify(new_password)

    def delete(self, username: str, password: str) -> bool:
        assert isinstance(users := self.datas["users"], dict)
        if username not in users:
            raise ValueError(f"user '{username}' not exists")

        if not self[username].verify(password):
            raise ValueError("password error")

        del users[username]
        return username not in self

    def create(self, username: str, password: str) -> Argon2Hasher:
        assert isinstance(users := self.datas["users"], dict)
        if username in users:
            raise ValueError(f"user '{username}' already exists")

        users.setdefault(username, self.encode(password).hashed)
        self.dumpf()

        return self[username]


class LdapConfig(BasicConfig):
    SECTION = "ldap"

    def __init__(self, config: BasicConfig):
        config.datas.setdefault(self.SECTION, {})
        super().__init__(config.path, config.datas)

    @property
    def server(self) -> str:
        return self.datas[self.SECTION]["server"]

    @property
    def bind_dn(self) -> str:
        return self.datas[self.SECTION]["bind_username"]

    @property
    def bind_pw(self) -> str:
        return self.datas[self.SECTION]["bind_password"]

    @property
    def base_dn(self) -> str:
        return self.datas[self.SECTION]["search_base"]

    @property
    def filter(self) -> str:
        return self.datas[self.SECTION]["search_filter"]

    @property
    def attributes(self) -> List[str]:
        return self.datas[self.SECTION]["search_attributes"]

    @property
    def client(self) -> LdapClient:
        return LdapInit(self.server).bind(self.bind_dn, self.bind_pw)
