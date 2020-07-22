import sys
from pathlib import Path
from typing import Optional
from urllib.parse import ParseResult


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

    def __init__(
        self,
        ssh_host_key_path: Path,
        ssh_host_cert_path: Path,
        vault_addr: ParseResult,
        vault_token: str,
        ssh_sign_path: str,
        ssh_hostname: str,
        renewal_threshold_days: int,
        on_renew: Optional[str],
        on_failure: Optional[str],
        debug: bool,
    ):
        self.addr = vault_addr
        self.ssh_host_key_path = ssh_host_key_path
        self.ssh_host_cert_path = ssh_host_cert_path
        self.token = vault_token
        self.ssh_sign_path = ssh_sign_path
        self.ssh_hostname = ssh_hostname
        self.renewal_threshold_days = renewal_threshold_days
        self.on_renew_hook = on_renew
        self.on_failure_hook = on_failure
        self.debug = debug

    @staticmethod
    def exit(return_code: int):
        sys.exit(return_code)


__all__ = ["Config"]
