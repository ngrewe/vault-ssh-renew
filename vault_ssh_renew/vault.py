import abc
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Optional
from urllib.parse import ParseResult

import requests

from .errors import RenewError


class VaultRenewInit(abc.ABC):
    @abc.abstractmethod
    def renew(self):
        ...


class VaultRenewDone(abc.ABC):
    @abc.abstractmethod
    def write_certificate(self):
        ...


class VaultRenewer(VaultRenewInit, VaultRenewDone):
    _url: str
    _token: str
    _public_key: str
    _hostname: str
    _cert_path: Path
    _signed_key: Optional[str]

    def __init__(
        self,
        addr: ParseResult,
        token: str,
        sign_path: str,
        public_key: str,
        hostname: str,
        cert_path: Path,
    ):
        self._url = addr.geturl() + "/v1/" + sign_path
        self._public_key = public_key
        self._token = token
        self._hostname = hostname
        self._cert_path = cert_path

    def renew(self) -> VaultRenewDone:
        response = requests.post(
            self._url, json=self._get_payload(), headers={"X-Vault-Token": self._token}
        )
        if response.status_code == 200:
            self._signed_key = response.json()["data"]["signed_key"]
        else:
            raise RenewError("Could not renew certificate: %s" % response.text)
        return self

    def write_certificate(self):
        assert self._signed_key is not None

        try:
            temp_file = NamedTemporaryFile(
                delete=False, dir=os.path.dirname(str(self._cert_path))
            )
        except OSError:
            # We might not be allowed to write to the certificate directory.
            # In that case, we fall back to TMPDIR. This is slightly less
            # safe if TMPDIR is on a different device since we cannot atomically
            # switch out the certificate.
            temp_file = NamedTemporaryFile(delete=False)

        with temp_file as tmp:
            tmp.write(self._signed_key.encode("utf-8"))
            tmp.flush()
            shutil.move(tmp.name, str(self._cert_path))

    def _get_payload(self) -> Dict[str, str]:
        return {
            "cert_type": "host",
            "public_key": self._public_key,
            "valid_principals": self._hostname,
        }

    @classmethod
    def build(
        cls,
        addr: ParseResult,
        token: str,
        sign_path: str,
        public_key: str,
        hostname: str,
        cert_path: Path,
    ) -> VaultRenewInit:
        return cls(addr, token, sign_path, public_key, hostname, cert_path)


__all__ = ["VaultRenewer"]
