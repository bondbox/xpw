# coding:utf-8

from errno import ECANCELED
import os
from typing import Optional
from typing import Sequence

from xhtml import FlaskProxy
from xhtml import LocaleTemplate
from xkits import add_command
from xkits import argp
from xkits import commands
from xkits import run_command

from xpw import AuthInit
from xpw.attribute import __urlhome__
from xpw.attribute import __version__
from xpw_locker import web


@add_command("xpw-locker", description="User access authentication")
def add_cmd(_arg: argp):
    pass


@run_command(add_cmd)
def run_cmd(cmds: commands) -> int:
    web.AUTH = AuthInit.from_file()
    web.PROXY = FlaskProxy("http://127.0.0.1:8000")
    web.TEMPLATE = LocaleTemplate(os.path.join(web.BASE, "resources"))
    web.app.run(host="0.0.0.0", port=3000)
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = commands()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501
