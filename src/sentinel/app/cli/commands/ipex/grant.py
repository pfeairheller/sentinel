# -*- encoding: utf-8 -*-
"""
KERI
watopnet.app.cli module

Watcher command line interface
"""

import argparse

from keri.app.cli.common import existing
from keri.vdr.credentialing import Regery

from sentinel.core.ipexing import create_extended_ipex_grant

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
parser.add_argument(
    "--said",
    "-s",
    help="credential self-addressing identifier",
    required=False,
    default="",
)

FORMAT = "%(asctime)s [sentinel] %(levelname)-8s %(message)s"


def launch(args):
    # Resolve the passcode from --passcode-file before merging, so an
    # explicit --passcode still wins and the config-file merge below sees
    # an already-resolved args.bran.
    with existing.existingHab(args.name, args.alias, args.base, args.bran) as (hby, hab):
        rgy = Regery(hby, args.name)

        exn, msg = create_extended_ipex_grant(hby, hab, rgy, args.said, "EFuzv-bG0g672ddljEGYl2nRQK9Ao2HZTQeYOT5xCt31")
        with open("grant.cesr", "wb") as grant_file:
            grant_file.write(exn.raw)
            grant_file.write(msg)
