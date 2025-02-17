# coding:utf-8

from os import urandom
from typing import Union

from argon2 import PasswordHasher
from argon2 import Type
from argon2.exceptions import VerifyMismatchError


class Secret():
    """Hashed password digest"""

    def __init__(self, key: str):
        self.__key: str = key

    def __hash__(self) -> int:
        return hash(self.key)

    def __repr__(self) -> str:
        return f"Secret({self.key})"

    def __str__(self) -> str:
        return self.key

    def __eq__(self, other: Union["Secret", str]) -> bool:
        return str(other) == self.key if isinstance(other, (Secret, str)) else False  # noqa:E501

    @property
    def key(self) -> str:
        """secret key"""
        return self.__key


class Salt():
    """Password salt"""
    MIN_LENGTH: int = 8  # minimum length
    DEF_LENGTH: int = 16  # default length

    def __init__(self, value: bytes):
        self.__value: bytes = value.ljust(self.MIN_LENGTH, b"x")

    @property
    def value(self) -> bytes:
        """salt value"""
        return self.__value

    @classmethod
    def format(cls, value: bytes, length: int = DEF_LENGTH) -> "Salt":
        """right-justified password salt"""
        return cls(value.rjust(length, b"x"))

    @classmethod
    def random(cls, length: int = DEF_LENGTH) -> "Salt":
        """generate random password salt"""
        return cls(urandom(length))

    @classmethod
    def generate(cls, value: Union[str, bytes, None] = None, length: int = DEF_LENGTH) -> "Salt":  # noqa:E501
        """generate password salt"""
        return cls.random(length) if value is None else cls.format(value.encode("utf-8") if isinstance(value, str) else value)  # noqa:E501


class Argon2Hasher():
    """Argon2 password hasher"""
    DEFAULT_TIME_COST: int = 8
    DEFAULT_MEMORY_COST: int = 65536
    DEFAULT_PARALLELISM: int = 4
    DEFAULT_HASH_LENGTH: int = 32
    DEFAULT_SALT_LENGTH: int = 16

    def __init__(self, hashed: str):
        self.__hashed: str = hashed
        if not isinstance(self.verify(__name__), bool):
            raise ValueError("Invalid hash")
        self.__secret: Secret = Secret(key=hashed.split("$")[-1])

    @property
    def hashed(self) -> str:
        """encoded hash"""
        return self.__hashed

    @property
    def secret(self) -> Secret:
        """secret key"""
        return self.__secret

    def verify(self, password: str) -> bool:
        """verify password is match"""
        try:
            return PasswordHasher().verify(self.hashed, password)
        except VerifyMismatchError:
            return False

    @classmethod
    def hash(cls, password: str, salt: Union[str, bytes, None] = None,
             time_cost: int = DEFAULT_TIME_COST,
             memory_cost: int = DEFAULT_MEMORY_COST,
             parallelism: int = DEFAULT_PARALLELISM,
             hash_len: int = DEFAULT_HASH_LENGTH,
             salt_len: int = DEFAULT_SALT_LENGTH) -> "Argon2Hasher":
        return cls(hashed=PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            encoding="utf-8",
            type=Type.ID
        ).hash(password, salt=Salt.generate(salt, salt_len).value))
