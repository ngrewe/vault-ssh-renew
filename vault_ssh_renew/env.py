import sys
from pathlib import Path
import socket
from typing import Optional
from urllib.parse import ParseResult

from environs import Env


class Config:

    addr: ParseResult
    token: str
    renewal_threshold_days: int
    ssh_sign_path: str
    ssh_hostname: str
    ssh_host_key_path: Path
    ssh_host_cert_path: Path
    on_renew_hook: Optional[str]
    on_failure_hook: Optional[str]
    debug: bool

    def __init__(self):
        env = Env()
        env.read_env()
        self.addr: ParseResult = env.url("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token: str = env.str("VAULT_TOKEN")
        self.renewal_threshold_days: int = env.int("VAULT_RENEW_THRESHOLD_DAYS", 7)
        self.ssh_sign_path: str = env.str("VAULT_SSH_SIGN_PATH")
        self.ssh_hostname = env.str("VAULT_SSH_HOSTNAME", socket.getfqdn())
        self.ssh_host_key_path: Path = env.path(
            "VAULT_SSH_HOST_KEY_PATH", "/etc/ssh/ssh_host_rsa_key.pub"
        )
        self.ssh_host_cert_path: Path = env.path(
            "VAULT_SSH_HOST_CERT_PATH", "/etc/ssh/ssh_host_rsa_key-cert.pub"
        )
        self.on_renew_hook: Optional[str] = env.str("VAULT_ON_RENEW_HOOK", None)
        self.on_failure_hook: Optional[str] = env.str("VAULT_ON_FAILURE_HOOK", None)
        self.debug: bool = env.bool("VAULT_DEBUG", False)

    @staticmethod
    def exit(return_code: int):
        sys.exit(return_code)


__all__ = ["Config"]
