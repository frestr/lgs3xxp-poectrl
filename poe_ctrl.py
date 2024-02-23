#!/usr/bin/env python3

import argparse
import logging as log
import os
import pathlib
import sys
import time
import urllib

import requests
import yaml
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import random
from urllib3.exceptions import InsecureRequestWarning


class LoginException(Exception):
    pass


class LoginSession:
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.session = requests.Session()

    def __enter__(self):
        log.info("Logging in...")
        self._login()
        log.info("Logged in")
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        log.info("Logging out...")
        self._logout()
        log.info("Logged out")

    def _login(self):
        log.info("Fetching RSA key")
        rsa_key = self._get_rsa_key()

        log.info("Encrypting login details")
        cipher = PKCS1_v1_5.new(rsa_key)
        plaintext = f"user={self.username}&password={self.password}&"
        ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

        sid = random.randint(10**10, 10**11)
        self.session.cookies.set("sessionID", f"UserId=127.0.0.1&-{sid}&")
        params = {
            "action": "login",
            "cred": ciphertext.hex(),
        }

        log.info("Sending login request")
        url = f"https://{self.hostname}/csd90d7adf/config/System.xml"
        response = self.session.get(
            url,
            params=params,
            verify=False,
        )

        bs = BeautifulSoup(response.text, features="xml")
        if bs.statusString.string != "OK":
            raise LoginException()

    def _logout(self):
        url = f"https://{self.hostname}/csd90d7adf/config/logOff_message.htm"
        response = self.session.get(
            url,
            verify=False,
        )

    def _get_rsa_key(self):

        class CurlyBracesSession(requests.Session):
            """Requests session that doesn't encode curly braces in URL"""

            def __init__(self):
                super().__init__()
                requests.urllib3.util.url.QUERY_CHARS.add("{")
                requests.urllib3.util.url.QUERY_CHARS.add("}")

            def send(self, *a, **kw):
                a[0].url = (
                    a[0]
                    .url.replace(urllib.parse.quote("{"), "{")
                    .replace(urllib.parse.quote("}"), "}")
                )
                return requests.Session.send(self, *a, **kw)

        cached_key_path = os.path.join(
            os.getenv("HOME"), ".cache", f"{self.hostname}.pem"
        )
        try:
            with open(cached_key_path, "r") as f:
                pem_key = f.read()
            log.info(f"Using cached RSA key from {cached_key_path}")
        except FileNotFoundError:
            log.info("No cached RSA key found. Will query switch instead.")

            url = f"https://{self.hostname}/csd90d7adf/config/device/wcd"
            session = CurlyBracesSession()
            response = session.get(url, params="{EncryptionSetting}", verify=False)

            bs = BeautifulSoup(response.text, features="xml")
            pem_key = bs.rsaPublicKey.string
            pathlib.Path(os.path.dirname(cached_key_path)).mkdir(
                parents=True, exist_ok=True
            )
            with open(cached_key_path, "w") as f:
                f.write(pem_key)
            log.info(f"Stored key at {cached_key_path}")

        return RSA.importKey(pem_key)


class PoeManager:
    def __init__(self, hostname, session):
        self.hostname = hostname
        self.session = session

    def print_status(self, labels={}):
        status = self._get_status()

        def print_line(lst):
            print(str("{:<15}" * len(lst)).format(*lst))

        columns = (
            "Port Num",
            "PoE Status",
            "Power Output",
            "Operation",
            "Label",
        )
        print_line(columns)
        print_line(["-" * len(c) for c in columns])
        for entry in status:
            vals = [entry[c] for c in columns if c in entry]
            idx = int(entry["Port Num"])
            if idx in labels:
                vals.append(labels[idx])
            print_line(vals)

    def enable_port(self, index):
        log.info(f"Enabling port {index}")
        self._set_port_state(index, True)
        log.info("Enabled")

    def disable_port(self, index):
        log.info(f"Disabling port {index}")
        self._set_port_state(index, False)
        log.info("Disabled")

    def _get_status(self):
        url = f"https://{self.hostname}/csd90d7adf/poe/system_poe_interface_m.htm?[pethPsePortTableVT]Filter:(pethPsePortGroupIndex=1)&&(ifOperStatus!=6)&&(rlPethPsePortSupportPoe!=2)"
        response = self.session.get(
            url,
            verify=False,
        )

        bs = BeautifulSoup(response.text, features="lxml")

        def find_poe_val(bs, label, index):
            return bs.find(
                "input",
                {"name": f"{label}$repeat?{index}"},
            )["value"]

        port_count = len(
            bs.find_all(
                "input", {"name": lambda x: x and "pethPsePortIndex$repeat" in x}
            )
        )

        poe_status = []
        for index in range(1, port_count + 1):
            port_status = {
                "Port Num": str(index),
                "PoE Status": (
                    {"1": "Enabled", "2": "Disabled"}[
                        find_poe_val(bs, "pethPsePortAdminEnable", index)
                    ]
                ),
                "Power Output": find_poe_val(bs, "rlPethPsePortOutputPower", index),
                "Operation": (
                    {
                        "1": "Disabled",
                        "2": "Searching",
                        "3": "Delivering Power",
                        "4": "Powering Up",
                        "5": "Test",
                        "6": "Fault",
                    }[find_poe_val(bs, "pethPsePortDetectionStatus", index)]
                ),
            }
            poe_status.append(port_status)

        return poe_status

    def _set_port_state(self, index, enabled):
        query_value = "1" if enabled else "2"

        url = f"https://{self.hostname}/csd90d7adf/poe/system_poe_interface_e.htm"
        backend_index = 48 + index
        data = f"restoreUrl=[pethPsePortTableVT]Filter:(rlPethPsePortSupportPoe+!=+2)^Query:pethPsePortGroupIndex=1@pethPsePortIndex={backend_index}&errorCollector=&rlPethPsePortTimeRangeName$VT=Type=100;Access=2;NumOfEnumerations=0;Range0=[0,32];Default+value=&rlPethPsePortSupportPoePlus$VT=Type=0;Access=1;NumOfEnumerations=2;Range0=[1,2];Default+value=1&pethPsePortTableVT$query=OK&pethPsePortGroupIndex$query=1&pethPsePortIndex$query={backend_index}&pethPsePortAdminEnable$query={query_value}&rlPethPsePortTimeRangeName$query=&rlPethPsePortSupportPoePlus$query=1&pethPsePortTableVT$endQuery=OK"

        response = self.session.post(
            url,
            verify=False,
            data=data,
        )


def switch_reachable(hostname):
    # Disable warnings about self-signed https certificate (not something we can change)
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    try:
        response = requests.get(
            f"https://{hostname}/csd90d7adf/config/log_off_page.htm",
            verify=False,
        )
    except requests.exceptions.ConnectionError:
        log.error(f"Switch ({hostname}) is unreachable")
        return False
    return True


def load_config(config_path):
    try:
        with open(config_path, "r") as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError:
                log.error("Unable to parse YAML config")
                raise
    except FileNotFoundError:
        pathlib.Path(os.path.dirname(config_path)).mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            f.write(
                "#hostname: 192.168.0.1\n"
                "#username: admin\n"
                "#password: admin\n"
                "#labels:\n"
                "#  1: foo\n"
                "#  2: bar\n"
                "#  3: baz\n"
            )
        log.error(
            f"No configuration file found at {config_path}; writing a sample file."
        )
        log.error(
            f"Please update {config_path} with your switch's info and re-run this program."
        )
        raise

    if not config:
        log.error("Invalid config")
        return Exception()
    return config


def main():
    # Define CLI arguments
    parser = argparse.ArgumentParser(
        prog="poe_ctrl",
        description="Remotely manage the state of PoE ports on a LGS308P switch",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="Print current status of PoE ports. If provided together with -e|-d|-c, will print status after update.",
    )
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--port",
        dest="port_num",
        action="store",
        metavar="PORT_NUM",
        type=int,
        help="Number of the port to operate on.",
    )
    port_group.add_argument(
        "-l",
        "--label",
        dest="port_label",
        action="store",
        metavar="PORT_LABEL",
        type=str,
        help="Label of the port to operate on",
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
    if not (args.status or args.port):
        parser.print_help()
        return 1

    if (args.port_num or args.port_label) and not (
        args.enable or args.disable or args.cycle
    ):
        parser.error("Port action must be provided")
    if (args.enable or args.disable or args.cycle) and not (
        args.port_num or args.port_label
    ):
        parser.error("Port number or label must be provided")

    # Set logging
    log.basicConfig(format="%(levelname)s: %(message)s")
    if args.verbose:
        log.basicConfig(
            format="%(levelname)s: %(message)s", level=log.DEBUG, force=True
        )

    # Read config
    config_path = os.path.join(os.getenv("HOME"), ".config", "poe_ctrl", "config.yaml")
    try:
        config = load_config(config_path)
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

    # Sanity check before continuinf
    if not switch_reachable(hostname):
        return 1

    # Login and process action
    try:
        with LoginSession(hostname, username, password) as session:
            manager = PoeManager(hostname, session)

            if args.enable:
                manager.enable_port(port_num)
            elif args.disable:
                manager.disable_port(port_num)
            elif args.cycle:
                manager.disable_port(port_num)
                time.sleep(5)
                manager.enable_port(port_num)

            if args.status:
                manager.print_status(labels)
    except LoginException as e:
        log.error("Login failed. Incorrect credentials?")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
