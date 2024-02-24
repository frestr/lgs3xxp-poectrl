import logging as log

import requests
from bs4 import BeautifulSoup


class InvalidPortException(Exception):
    """Switch port is invalid"""


class PoeManager:
    """Manages the PoE state of switch ports."""

    def __init__(self, hostname: str, session: requests.Session):
        self.hostname = hostname
        self.session = session

    def print_status(self, labels: dict = {}) -> None:
        """Print the PoE status of all ports as a formatted table."""

        def print_line(lst):
            print(str("{:<18}" * len(lst)).format(*lst))

        status = self._get_status()

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

    def enable_port(self, index: int) -> None:
        """Enable PoE power on the specified port."""
        log.info(f"Enabling port {index}")
        self._set_port_state(index, True)
        log.info("Enabled")

    def disable_port(self, index: int) -> None:
        """Disable PoE power on the specified port."""
        log.info(f"Disabling port {index}")
        self._set_port_state(index, False)
        log.info("Disabled")

    def _get_status(self) -> list[dict]:
        """Get the PoE status of all ports."""

        def find_poe_val(bs, label, index):
            return bs.find(
                "input",
                {"name": f"{label}$repeat?{index}"},
            )["value"]

        url = f"https://{self.hostname}/csd90d7adf/poe/system_poe_interface_m.htm"
        params = (
            "[pethPsePortTableVT]Filter:"
            "(pethPsePortGroupIndex=1)&&"
            "(ifOperStatus!=6)&&"
            "(rlPethPsePortSupportPoe!=2)"
        )
        response = self.session.get(
            url,
            params=params,
            verify=False,
        )

        bs = BeautifulSoup(response.text, features="lxml")

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

    def _set_port_state(self, index: int, enabled: bool) -> None:
        """Set the specified port to enabled/on or disabled/off"""
        query_value = "1" if enabled else "2"

        url = f"https://{self.hostname}/csd90d7adf/poe/system_poe_interface_e.htm"
        backend_index = 48 + index
        data = (
            "restoreUrl=[pethPsePortTableVT]Filter:(rlPethPsePortSupportPoe+!=+2)^"
            f"Query:pethPsePortGroupIndex=1@pethPsePortIndex={backend_index}&"
            "errorCollector=&rlPethPsePortTimeRangeName$VT=Type=100;Access=2;NumOfEnumerations=0;"
            "Range0=[0,32];Default+value=&rlPethPsePortSupportPoePlus$VT=Type=0;Access=1;"
            "NumOfEnumerations=2;Range0=[1,2];Default+value=1&pethPsePortTableVT$query=OK&"
            f"pethPsePortGroupIndex$query=1&pethPsePortIndex$query={backend_index}&"
            f"pethPsePortAdminEnable$query={query_value}&rlPethPsePortTimeRangeName$query=&"
            "rlPethPsePortSupportPoePlus$query=1&pethPsePortTableVT$endQuery=OK"
        )

        response = self.session.post(
            url,
            verify=False,
            data=data,
        )

        # Check if response indicates that the port was invalid
        bs = BeautifulSoup(response.text, features="lxml")
        if bs.find(
            "input",
            {"name": lambda x: x and x.startswith("mibError?")},
        ):
            raise InvalidPortException(f"Invalid port number ({index})")
