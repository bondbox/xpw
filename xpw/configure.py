# coding:utf-8

from typing import Any
from typing import Dict
from typing import List

from xpw.ldapauth import LdapClient
from xpw.ldapauth import LdapInit
from xpw.password import Argon2Hasher

CONFIG_DATA_TYPE = Dict[str, Any]
DEFAULT_CONFIG_FILE = "xpwauth"


class BasicConfig():
    def __init__(self, datas: CONFIG_DATA_TYPE):
        self.__datas: CONFIG_DATA_TYPE = datas

    @property
    def datas(self) -> CONFIG_DATA_TYPE:
        return self.__datas

    @classmethod
    def loadf(cls, path: str = DEFAULT_CONFIG_FILE) -> CONFIG_DATA_TYPE:
        """load config from toml file"""
        from toml import load  # pylint: disable=import-outside-toplevel

        return load(path)


class Argon2Config(BasicConfig):
    TYPE = "argon2"

    def __init__(self, datas: CONFIG_DATA_TYPE):
        datas.setdefault(self.TYPE, {})
        datas.setdefault("users", {})
        super().__init__(datas)

    def __getitem__(self, user: str) -> Argon2Hasher:
        return self.generate(self.datas["users"][user])

    @property
    def time_cost(self) -> int:
        return self.datas[self.TYPE].get("time_cost", Argon2Hasher.DEFAULT_TIME_COST)  # noqa:E501

    @property
    def memory_cost(self) -> int:
        return self.datas[self.TYPE].get("memory_cost", Argon2Hasher.DEFAULT_MEMORY_COST)  # noqa:E501

    @property
    def parallelism(self) -> int:
        return self.datas[self.TYPE].get("parallelism", Argon2Hasher.DEFAULT_PARALLELISM)  # noqa:E501

    @property
    def hash_len(self) -> int:
        return self.datas[self.TYPE].get("hash_length", Argon2Hasher.DEFAULT_HASH_LENGTH)  # noqa:E501

    @property
    def salt_len(self) -> int:
        return self.datas[self.TYPE].get("salt_length", Argon2Hasher.DEFAULT_SALT_LENGTH)  # noqa:E501

    @property
    def salt(self) -> str:
        return self.datas[self.TYPE].get("salt", None)

    def generate(self, password: str) -> Argon2Hasher:
        return Argon2Hasher(password) if password.startswith("$") else self.encode(password)  # noqa:E501

    def encode(self, password: str) -> Argon2Hasher:
        return Argon2Hasher.hash(password=password, salt=self.salt,
                                 time_cost=self.time_cost,
                                 memory_cost=self.memory_cost,
                                 parallelism=self.parallelism,
                                 hash_len=self.hash_len,
                                 salt_len=self.salt_len)


class LdapConfig(BasicConfig):
    TYPE = "ldap"

    def __init__(self, datas: CONFIG_DATA_TYPE):
        datas.setdefault(self.TYPE, {})
        super().__init__(datas)

    @property
    def server(self) -> str:
        return self.datas[self.TYPE]["server"]

    @property
    def bind_dn(self) -> str:
        return self.datas[self.TYPE]["bind_username"]

    @property
    def bind_pw(self) -> str:
        return self.datas[self.TYPE]["bind_password"]

    @property
    def base_dn(self) -> str:
        return self.datas[self.TYPE]["search_base"]

    @property
    def filter(self) -> str:
        return self.datas[self.TYPE]["search_filter"]

    @property
    def attributes(self) -> List[str]:
        return self.datas[self.TYPE]["search_attributes"]

    @property
    def client(self) -> LdapClient:
        return LdapInit(self.server).bind(self.bind_dn, self.bind_pw)
