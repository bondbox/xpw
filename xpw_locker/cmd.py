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
from xpw import DEFAULT_CONFIG_FILE
from xpw import SessionPool
from xpw.attribute import __urlhome__
from xpw.attribute import __version__
from xpw_locker import web


@add_command("xpw-locker", description="Access authentication")
def add_cmd(_arg: argp):
    _arg.add_argument("--config", type=str, dest="config_file",
                      help="Authentication configuration", metavar="FILE",
                      default=os.getenv("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    _arg.add_argument("--expires", type=int, dest="lifetime",
                      help="Session login interval hours", metavar="HOUR",
                      default=int(os.getenv("EXPIRES", "1")))
    _arg.add_argument("--target", type=str, dest="target_url",
                      help="Proxy target url", metavar="URL",
                      default=os.getenv("TARGET_URL", "http://localhost"))
    _arg.add_argument("--host", type=str, dest="listen_address",
                      help="Listen address", metavar="ADDR",
                      default=os.getenv("LISTEN_ADDRESS", "0.0.0.0"))
    _arg.add_argument("--port", type=int, dest="listen_port",
                      help="Listen port", metavar="PORT",
                      default=int(os.getenv("LISTEN_PORT", "3000")))


@run_command(add_cmd)
def run_cmd(cmds: commands) -> int:
    web.PORT = cmds.args.listen_port
    web.HOST = cmds.args.listen_address
    web.AUTH = AuthInit.from_file(cmds.args.config_file)
    web.PROXY = FlaskProxy(cmds.args.target_url)
    web.SESSIONS = SessionPool(lifetime=cmds.args.lifetime * 3600)
    web.TEMPLATE = LocaleTemplate(os.path.join(web.BASE, "resources"))
    web.run()
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = commands()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501
