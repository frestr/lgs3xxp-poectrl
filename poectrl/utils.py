import logging as log
import os
import pathlib

import requests
import yaml
from urllib3.exceptions import InsecureRequestWarning


def switch_reachable(hostname: str) -> bool:
    """Check if the switch is reachable by making an HTTP request to the specified hostname."""
    # Disable warnings about self-signed https certificate (not something we can change)
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    try:
        response = requests.get(
            f"https://{hostname}/csd90d7adf/config/log_off_page.htm",
            verify=False,
        )
    except requests.exceptions.ConnectionError as e:
        log.error(
            f"Unable to connect to switch ({hostname}). Run with -v for more details."
        )
        log.debug(e)
        return False
    return True


def load_config(config_path: str) -> dict:
    """Load configuration file from the specified path."""
    try:
        with open(config_path, "r") as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as e:
                log.error("Unable to parse YAML config")
                log.debug(e)
                raise
    except FileNotFoundError:
        log.error(
            f"No configuration file found at {config_path}; writing a sample file."
        )
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
            f"Please update {config_path} with your switch's info and re-run this program."
        )
        raise

    if not config:
        log.error(f"Invalid config ({config_path})")
        raise Exception()
    return config


def get_config_path() -> str:
    """Get the path of the configuration file."""
    return os.path.join(os.getenv("HOME"), ".config", "poectrl", "config.yaml")


def get_cached_key_path(hostname: str) -> str:
    """Get the path of the cached RSA key for the specified hostname."""
    return os.path.join(os.getenv("HOME"), ".cache", "poectrl", f"{hostname}.pem")
