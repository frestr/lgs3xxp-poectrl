#!/usr/bin/env python3

import argparse
import logging as log
import sys
import time
import urllib

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import random
from urllib3.exceptions import InsecureRequestWarning


class LoginSession:
    def __init__(self, ip, username, password):
        self.ip = ip
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
        url = f"https://{self.ip}/csd90d7adf/config/System.xml"
        response = self.session.get(
            url,
            params=params,
            verify=False,
        )

        bs = BeautifulSoup(response.text, features="xml")
        if bs.statusString.string != "OK":
            raise Exception("login failed")

    def _logout(self):
        url = f"https://{self.ip}/csd90d7adf/config/logOff_message.htm"
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

        url = f"https://{self.ip}/csd90d7adf/config/device/wcd"
        session = CurlyBracesSession()
        response = session.get(url, params="{EncryptionSetting}", verify=False)

        bs = BeautifulSoup(response.text, features="xml")
        pem_key = bs.rsaPublicKey.string
        return RSA.importKey(pem_key)


class PoeManager:
    def __init__(self, ip, session):
        self.ip = ip
        self.session = session

    def print_status(self):
        status = self._get_status()

        def print_line(lst):
            print(str("{:<20}" * len(lst)).format(*lst))

        columns = ("Port Num", "PoE Status", "Power Consumption", "Operational Status")
        print_line(columns)
        for entry in status:
            print_line(entry.values())

    def enable_port(self, index):
        log.info(f"Enabling port {index}")
        self._set_port_state(index, True)
        log.info("Enabled")

    def disable_port(self, index):
        log.info(f"Disabling port {index}")
        self._set_port_state(index, False)
        log.info("Disabled")

    def _get_status(self):
        url = f"https://{self.ip}/csd90d7adf/poe/system_poe_interface_m.htm?[pethPsePortTableVT]Filter:(pethPsePortGroupIndex=1)&&(ifOperStatus!=6)&&(rlPethPsePortSupportPoe!=2)"
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
                "Power Consumption": find_poe_val(
                    bs, "rlPethPsePortOutputPower", index
                ),
                "Operational Status": (
                    {
                        "1": "Disabled",
                        "2": "Searching",
                        "3": "Delivering Power",
                        "4": "Fault",
                        "5": "Test",
                        "6": "Other Fault",
                    }[find_poe_val(bs, "pethPsePortDetectionStatus", index)]
                ),
            }
            poe_status.append(port_status)

        return poe_status

    def _set_port_state(self, index, enabled):
        query_value = "1" if enabled else "2"

        url = f"https://{self.ip}/csd90d7adf/poe/system_poe_interface_e.htm"
        backend_index = 48 + index
        data = f"restoreUrl=[pethPsePortTableVT]Filter:(rlPethPsePortSupportPoe+!=+2)^Query:pethPsePortGroupIndex=1@pethPsePortIndex={backend_index}&errorCollector=&rlPethPsePortTimeRangeName$VT=Type=100;Access=2;NumOfEnumerations=0;Range0=[0,32];Default+value=&rlPethPsePortSupportPoePlus$VT=Type=0;Access=1;NumOfEnumerations=2;Range0=[1,2];Default+value=1&pethPsePortTableVT$query=OK&pethPsePortGroupIndex$query=1&pethPsePortIndex$query={backend_index}&pethPsePortAdminEnable$query={query_value}&rlPethPsePortTimeRangeName$query=&rlPethPsePortSupportPoePlus$query=1&pethPsePortTableVT$endQuery=OK"

        response = self.session.post(
            url,
            verify=False,
            data=data,
        )


def switch_reachable(ip):
    # Disable warnings about self-signed https certificate (not something we can change)
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    try:
        response = requests.get(
            f"https://{ip}/csd90d7adf/config/log_off_page.htm",
            verify=False,
        )
    except requests.exceptions.ConnectionError:
        log.error(f"Switch ({ip}) is unreachable")
        return False
    return True


def main():
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
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        action="store",
        metavar="PORT",
        type=int,
        help="The port to operate on.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-e",
        "--enable",
        action="store_true",
        help="Enable power on the specified port",
    )
    group.add_argument(
        "-d",
        "--disable",
        action="store_true",
        help="Disable power on the specified port",
    )
    group.add_argument(
        "-c",
        "--cycle",
        action="store_true",
        help="Power cycle the specified port",
    )
    args = parser.parse_args()
    if not (args.status or args.port):
        parser.print_help()
        return 1

    if args.port and not (args.enable or args.disable or args.cycle):
        parser.error("Port action must be provided")
    if (args.enable or args.disable or args.cycle) and not args.port:
        parser.error("Port must be provided")

    log.basicConfig(format="%(levelname)s: %(message)s")
    if args.verbose:
        log.basicConfig(
            format="%(levelname)s: %(message)s", level=log.DEBUG, force=True
        )

    ip = "192.168.1.173"
    username = "admin2"
    password = "foobar"

    if not switch_reachable(ip):
        return 1

    with LoginSession(ip, username, password) as session:
        manager = PoeManager(ip, session)

        p = args.port

        if args.enable:
            manager.enable_port(p)
        elif args.disable:
            manager.disable_port(p)
        elif args.cycle:
            manager.disable_port(p)
            time.sleep(1)
            manager.enable_port(p)

        if args.status:
            if args.enable or args.disable or args.cycle:
                time.sleep(1)
            manager.print_status()

    return 0


if __name__ == "__main__":
    sys.exit(main())
