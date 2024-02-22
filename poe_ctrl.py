#!/usr/bin/env python3

import argparse
import logging as log
import subprocess
import sys
import urllib

import requests
import urllib3
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import random
from urllib3.exceptions import InsecureRequestWarning


def get_rsa_key(ip):

    class CurlyBracesSession(requests.Session):
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

    url = f"https://{ip}/csd90d7adf/config/device/wcd"
    session = CurlyBracesSession()
    response = session.get(url, params="{EncryptionSetting}", verify=False)

    s = BeautifulSoup(response.text, features="xml")
    pem_key = s.rsaPublicKey.string
    return RSA.importKey(pem_key)


def login(ip, username, password):
    log.info("Fetching RSA key")
    rsa_key = get_rsa_key(ip)

    log.info("Encrypting login details")
    cipher = PKCS1_v1_5.new(rsa_key)
    plaintext = f"user={username}&password={password}&"
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

    sid = random.randint(10**10, 10**11)
    cookies = {
        # 'admin2_numberOfEntriesPerPage': '50',
        # 'activeLangId': 'English',
        # 'userStatus': 'ok',
        "sessionID": f"UserId=127.0.0.1&-{sid}&",
        # 'usernme': 'admin2',
        # 'pg': '00000000000000000000000000000000000000000000000000000',
        # 'LogOff_Reason': 'Manual',
        # 'firstWelcomeBanner': 'false',
        # 'isStackableDevice': 'false',
    }

    params = {
        "action": "login",
        "cred": ciphertext.hex(),
    }

    log.info("Sending login request")
    url = f"https://{ip}/csd90d7adf/config/System.xml"
    response = requests.get(
        url,
        params=params,
        cookies=cookies,
        verify=False,
    )

    s = BeautifulSoup(response.text, features="xml")
    if s.statusString.string != "OK":
        raise Exception("login failed")

    return cookies


def get_poe_status(ip, cookies):
    url = f"https://{ip}/csd90d7adf/poe/system_poe_interface_m.htm?[pethPsePortTableVT]Filter:(pethPsePortGroupIndex=1)&&(ifOperStatus!=6)&&(rlPethPsePortSupportPoe!=2)"
    response = requests.get(
        url,
        cookies=cookies,
        verify=False,
    )

    s = BeautifulSoup(response.text, features="lxml")

    def find_poe_val(s, label, idx):
        return s.find(
            "input",
            {"name": f"{label}$repeat?{idx}"},
        )["value"]

    port_count = len(
        s.find_all("input", {"name": lambda x: x and "pethPsePortIndex$repeat" in x})
    )

    poe_status = []
    for idx in range(1, port_count + 1):
        port_status = {
            "Port Num": str(idx),
            "PoE Status": (
                {"1": "Enabled", "2": "Disabled"}[
                    find_poe_val(s, "pethPsePortAdminEnable", idx)
                ]
            ),
            "Power Consumption": find_poe_val(s, "rlPethPsePortOutputPower", idx),
            "Operational Status": (
                {
                    "1": "Disabled",
                    "2": "Searching",
                    "3": "Delivering Power",
                    "4": "Fault",
                    "5": "Test",
                    "6": "Other Fault",
                }[find_poe_val(s, "pethPsePortDetectionStatus", idx)]
            ),
        }
        poe_status.append(port_status)

    return poe_status


def print_table(poe_status):
    def print_line(lst):
        print(str("{:<20}" * len(lst)).format(*lst))

    columns = ("Port Num", "PoE Status", "Power Consumption", "Operational Status")
    print_line(columns)
    for status in poe_status:
        print_line(status.values())


def disable_port(ip, cookies, port_idx):
    set_port_status(ip, cookies, port_idx, False)


def enable_port(ip, cookies, port_idx):
    set_port_status(ip, cookies, port_idx, True)


def set_port_status(ip, cookies, port_idx, enabled):
    query_value = "1" if enabled else "2"

    cookie = f"sessionID={cookies['sessionID']}"
    url = f"https://{ip}/csd90d7adf/poe/system_poe_interface_e.htm"
    backend_idx = 48 + port_idx
    data = f"restoreUrl=[pethPsePortTableVT]Filter:(rlPethPsePortSupportPoe+!=+2)^Query:pethPsePortGroupIndex=1@pethPsePortIndex={backend_idx}&errorCollector=&rlPethPsePortTimeRangeName$VT=Type=100;Access=2;NumOfEnumerations=0;Range0=[0,32];Default+value=&rlPethPsePortSupportPoePlus$VT=Type=0;Access=1;NumOfEnumerations=2;Range0=[1,2];Default+value=1&pethPsePortTableVT$query=OK&pethPsePortGroupIndex$query=1&pethPsePortIndex$query={backend_idx}&pethPsePortAdminEnable$query={query_value}&rlPethPsePortTimeRangeName$query=&rlPethPsePortSupportPoePlus$query=1&pethPsePortTableVT$endQuery=OK"

    response = requests.post(
        url,
        cookies=cookies,
        verify=False,
        data=data,
    )


def logout(ip, cookies):
    url = f"https://{ip}/csd90d7adf/config/logOff_message.htm"
    response = requests.get(
        url,
        cookies=cookies,
        verify=False,
    )


def main():
    parser = argparse.ArgumentParser(
        prog="ProgramName",
        description="What the program does",
        epilog="Text at the bottom of help",
    )
    parser.add_argument("-v", "--verbose", action="store_true")  # on/off flag
    args = parser.parse_args()

    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose output.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")

    ip = "192.168.1.173"
    username = "admin2"
    password = "foobar"

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    try:
        response = requests.get(
            f"https://{ip}/csd90d7adf/config/log_off_page.htm",
            verify=False,
        )
    except requests.exceptions.ConnectionError:
        log.error(f"Switch ({ip}) is unreachable")
        return 1

    log.info("Logging in...")
    cookies = login(ip, username, password)
    log.info("Logged in")

    status = get_poe_status(ip, cookies)
    print_table(status)

    log.info("Disabling port 3")
    disable_port(ip, cookies, 3)
    log.info("Disabled")

    status = get_poe_status(ip, cookies)
    print_table(status)

    log.info("Enabling port 3")
    enable_port(ip, cookies, 3)
    log.info("Enabled")

    status = get_poe_status(ip, cookies)
    print_table(status)

    log.info("Logging out...")
    logout(ip, cookies)
    log.info("Logged out")

    return 0


if __name__ == "__main__":
    sys.exit(main())
