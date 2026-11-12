# -*- encoding: utf-8 -*-
"""
KERI
watopnet.app.cli module

Watcher command line interface
"""

import argparse

from keri.app.cli.common import existing
from keri.core import serdering
from keri.vdr.credentialing import Regery

from sentinel.core.ipexing import create_extended_ipex_grant, IpexExtendedGrantHandler

d = "Runs a test command"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument(
    "--name", "-n", help="Name of the database environment", required=False
)
parser.add_argument(
    "--alias",
    "-a",
    help="human readable alias for the new identifier prefix",
    required=False,
)
parser.add_argument(
    "--passcode",
    "-p",
    help="22 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)  # passcode => bran
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)


def launch(args):
    with existing.existingHab(args.name, args.alias, args.base, args.bran) as (hby, hab):
        rgy = Regery(hby, args.name)

        with open("grant.cesr", "rb") as grant_file:
            serder = serdering.SerderKERI(raw=grant_file.read())

            pd = serder.ked.get("a", {}).get("pd", None)
            if not pd:
                raise ValueError("Invalid grant CESR file")

            handler = IpexExtendedGrantHandler(hby, hab, rgy)
            handler.process_percolated_discovery(pd)

