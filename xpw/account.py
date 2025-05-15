# coding:utf-8

from os import makedirs
from os.path import abspath
from os.path import dirname
from os.path import exists
from os.path import isdir
from os.path import join
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from xkits_lib.unit import TimeUnit

from xpw.authorize import AuthInit
from xpw.authorize import TokenAuth
from xpw.configure import DEFAULT_CONFIG_FILE
from xpw.session import SessionKeys
from xpw.session import SessionUser


class Profile():
    def __init__(self, user: str, base: str, root: bool = False):
        workspace: str = join(base, user)
        self.__administrator: bool = root
        self.__workspace: str = workspace
        self.__identity: str = user
        self.__username: str = user
        self.__catalog: str = base

    @property
    def administrator(self) -> bool:
        return self.__administrator

    @property
    def workspace(self) -> str:
        return self.__workspace

    @property
    def identity(self) -> str:
        return self.__identity

    @property
    def username(self) -> str:
        return self.__username

    @property
    def catalog(self) -> str:
        return self.__catalog


class Account():
    ACCOUNT_SECTION = "account"
    ADMIN_SECTION = "admin"

    def __init__(self, auth: TokenAuth, lifetime: Optional[TimeUnit] = 2592000,
                 secret_key: Optional[str] = None):  # expires in 30 days
        if lifetime is None:
            lifetime = auth.config.lifetime

        base: str = abspath(auth.config.datas.get("workspace", dirname(auth.config.path)))  # noqa:E501
        keys: SessionKeys = SessionKeys(secret_key or auth.config.secret_key, lifetime)  # noqa:E501

        auth.config.datas.setdefault(self.ADMIN_SECTION, {"user": ""})
        section: Dict[str, Any] = auth.config.datas[self.ADMIN_SECTION]
        if isinstance(admin := section["user"], str):
            section["user"] = [user for item in admin.split(",") if (user := item.strip())]  # noqa:E501
        assert isinstance(section["user"], list)

        if not exists(base):
            makedirs(base)  # pragma: no cover
        assert isdir(base)

        self.__tickets: SessionKeys = keys
        self.__members: TokenAuth = auth
        self.__catalog: str = base

    @property
    def tickets(self) -> SessionKeys:
        return self.__tickets

    @property
    def members(self) -> TokenAuth:
        return self.__members

    @property
    def catalog(self) -> str:
        return self.__catalog

    @property
    def options(self) -> Dict[str, Any]:
        return self.members.config.datas.get(self.ACCOUNT_SECTION, {})

    @property
    def allow_register(self) -> bool:
        return bool(self.options.get("register"))

    @property
    def allow_terminate(self) -> bool:
        return bool(self.options.get("terminate"))

    @property
    def admin_options(self) -> Dict[str, Any]:
        return self.members.config.datas.get(self.ADMIN_SECTION, {})

    @property
    def administrators(self) -> List[str]:
        return self.admin_options["user"]

    @property
    def first_user_is_admin(self) -> bool:
        return bool(self.admin_options.get("first_user"))

    @property
    def allow_admin_create_user(self) -> bool:
        return bool(self.admin_options.get("create_user"))

    @property
    def allow_admin_delete_user(self) -> bool:
        return bool(self.admin_options.get("delete_user"))

    def fetch(self, username: Optional[str]) -> Optional[Profile]:
        if username:
            root: bool = username in self.administrators
            return Profile(username, self.catalog, root)
        return None

    def check(self, session_id: str, secret_key: Optional[str] = None) -> bool:
        return self.tickets.verify(session_id, secret_key)

    def login(self, username: str, password: str,
              session_id: Optional[str] = None,
              secret_key: Optional[str] = None
              ) -> Optional[SessionUser]:
        identity: Optional[str] = self.members.verify(username, password)
        if username == "" and isinstance(identity, str) and identity != "":
            username = identity

        if username != identity:
            return None

        user: SessionUser = self.tickets.search(session_id).data
        self.tickets.sign_in(user.session_id, secret_key, username)
        return user

    def logout(self, username: str) -> bool:
        sessions = [i for i in self.tickets if self.tickets[i].data.identity == username]  # noqa:E501
        for session_id in sessions:
            self.tickets.sign_out(session_id)
        return True

    def generate(self, session_id: str, secret_key: Optional[str] = None, note: str = "") -> Optional[str]:  # noqa:E501
        """generate random token for authenticated user"""
        if (identity := self.tickets.lookup(session_id, secret_key)) is not None:  # noqa:E501
            return self.members.generate_token(note=note, user=identity)
        return None

    def register(self, username: str, password: str) -> Optional[Profile]:
        if not self.allow_register:
            raise PermissionError("register new account is disabled")

        user: Optional[str] = self.members.create_user(username, password)
        if self.first_user_is_admin and user and len(self.administrators) == 0:
            self.administrators.append(user)
            self.members.config.dumpf()
        return self.fetch(user)

    def terminate(self, username: str, password: str) -> bool:
        if not self.allow_terminate:
            raise PermissionError("terminate account is disabled")

        if len(self.administrators) <= 1 and username in self.administrators:
            raise PermissionError(f"administrator '{username}' cannot be terminated")  # noqa:E501

        # step 1: force verify username/password and logout accout
        if self.members.verify_password(username, password) == username and self.logout(username):  # noqa:E501
            # step 2: delete all tokens associated with the user
            for token in [t.hash for t in self.members.tokens.values() if t.user == username]:  # noqa:E501
                self.members.delete_token(token)
            # step 3: delete the user account
            return self.members.delete_user(username, password)
        return False

    @classmethod
    def from_file(cls, config: str = DEFAULT_CONFIG_FILE,
                  lifetime: Optional[TimeUnit] = None,
                  secret_key: Optional[str] = None) -> "Account":
        auth: TokenAuth = AuthInit.from_file(path=abspath(config))
        return cls(auth=auth, lifetime=lifetime, secret_key=secret_key)
