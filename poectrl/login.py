import logging as log
import os
import pathlib
import urllib

import requests
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
