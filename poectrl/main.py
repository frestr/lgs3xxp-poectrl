import argparse
import logging as log
import os
import time

from . import login, manager, utils


def main():
    # Define CLI arguments
    parser = argparse.ArgumentParser(
        prog="poectrl",
        description="Manage the state of PoE ports on a LGS3XXP switch",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="Print current status of PoE ports. "
        "If provided together with -e|-d|-c, will print status after update.",
    )
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--port",
        dest="port_num",
        action="store",
        metavar="PORT_NUM",
        type=int,
        help="Port number to operate on.",
    )
    port_group.add_argument(
        "-l",
        "--label",
        dest="port_label",
        action="store",
        metavar="PORT_LABEL",
        type=str,
        help="Port label to operate on",
    )
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "-e",
        "--enable",
        action="store_true",
        help="Enable power on the specified port",
    )
    action_group.add_argument(
        "-d",
        "--disable",
        action="store_true",
        help="Disable power on the specified port",
    )
    action_group.add_argument(
        "-c",
        "--cycle",
        action="store_true",
        help="Power cycle the specified port",
    )

    # Validate CLI arguments
    args = parser.parse_args()
    port_num_provided = args.port_num is not None
    port_label_provided = args.port_label is not None
    if not (args.status or port_num_provided or port_label_provided):
        parser.print_help()
        return 1

    if (port_num_provided or port_label_provided) and not (
        args.enable or args.disable or args.cycle
    ):
        parser.error("Port action must be provided")
    if (args.enable or args.disable or args.cycle) and not (
        port_num_provided or port_label_provided
    ):
        parser.error("Port number or label must be provided")

    # Set logging
    log.basicConfig(format="%(levelname)s: %(message)s")
    if args.verbose:
        log.basicConfig(
            format="%(levelname)s: %(message)s", level=log.DEBUG, force=True
        )

    # Read config
    try:
        config = utils.load_config(utils.get_config_path())
    except Exception:
        return 1

    try:
        hostname = config["hostname"]
        username = config["username"]
        password = config["password"]
    except KeyError as e:
        log.error(f"Config is missing required parameter: {e}")
        return 1

    labels = config["labels"] if "labels" in config else {}

    # Validate specified label
    if args.port_label:
        if args.port_label not in labels.values():
            log.error("Specified port label is not in config")
            return 1
        if list(labels.values()).count(args.port_label) != 1:
            log.error(
                "More than one port has the specified label. "
                "Please specify a port number instead."
            )
            return 1

    # Determine port number
    port_num = (
        list(labels.keys())[list(labels.values()).index(args.port_label)]
        if args.port_label
        else args.port_num
    )

    # Sanity check before continuing
    if not utils.switch_reachable(hostname):
        return 1

    # Login and process action
    try:
        with login.LoginSession(hostname, username, password) as session:
            m = manager.PoeManager(hostname, session)

            if args.enable:
                m.enable_port(port_num)
            elif args.disable:
                m.disable_port(port_num)
            elif args.cycle:
                m.disable_port(port_num)
                time.sleep(5)
                m.enable_port(port_num)

            if args.status:
                m.print_status(labels)
    except (login.LoginException, manager.InvalidPortException) as e:
        log.error(e)
        return 1

    return 0
