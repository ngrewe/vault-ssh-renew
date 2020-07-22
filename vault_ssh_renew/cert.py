import abc
import base64
from datetime import timedelta, datetime, timezone
from pathlib import Path
from typing import Optional, cast, Tuple, Dict, Type

from paramiko import Message

from .errors import RenewError


class HostCertificateInit(abc.ABC):
    @abc.abstractmethod
    def read(self) -> "HostCertificateValidate":
        """
        Read the certificate and key information into memory
        :return:
        """
        ...


class HostCertificateValidate(abc.ABC):
    @abc.abstractmethod
    def check_renewal_required(self, limit: timedelta) -> "HostCertificateStatus":
        """
        Parse the certificate to find out whether it needs to be renewed
        :param limit: The amount of lifetime the certificate should have left
        :return:
        """
        ...


class HostCertificateStatus:
    needs_renewal: bool

    def __init__(self, parent: "HostCertificate", needs_renewal: bool):
        self._parent = parent
        self.needs_renewal = needs_renewal

    @property
    def public_key(self) -> str:
        return self._parent.public_key


class HostCertificate:

    _key_path: Path
    _cert_path: Path
    public_key: Optional[str]
    cert_type: Optional[str]
    cert_data: Optional[Message]

    def __init__(self, key_path: Path, cert_path: Path):
        self._key_path = key_path
        self._cert_path = cert_path
        self.public_key = None

    @classmethod
    def get(cls, key_path: Path, cert_path: Path) -> HostCertificateInit:
        return cast(HostCertificateInit, cls(key_path, cert_path))

    def read(self) -> HostCertificateValidate:
        self.public_key = self._key_path.read_text(encoding="utf-8")
        if not self._cert_path.exists():
            return HostCertificateStatusNoCert(self, True)
        certificate_contents = self._cert_path.read_text(encoding="utf-8").split(" ")
        if len(certificate_contents) != 2:
            raise RenewError("Invalid certificate file")
        self.cert_type = certificate_contents[0]
        self.cert_data = Message(base64.b64decode(certificate_contents[1]))
        return SomeHostCertificateValidate.factor(self)


class HostCertificateStatusNoCert(HostCertificateStatus, HostCertificateValidate):
    def check_renewal_required(self, limit: timedelta) -> "HostCertificateStatus":
        return self


CERT_TYPE_MAP: Dict[str, Type["SomeHostCertificateValidate"]] = {}


def register_for(*cert_types: str):
    def _register(
        cls: Type["SomeHostCertificateValidate"],
    ) -> Type["SomeHostCertificateValidate"]:
        for cert_type in cert_types:
            if cert_type in CERT_TYPE_MAP:
                raise RenewError(
                    "Type %s already registered to %s"
                    % (cert_type, CERT_TYPE_MAP[cert_type].__name__)
                )
            CERT_TYPE_MAP[cert_type] = cls
        return cls

    return _register


class SomeHostCertificateValidate(HostCertificateValidate, abc.ABC):
    def __init__(self, parent: HostCertificate):
        self._parent = parent

    @classmethod
    def factor(cls, parent: HostCertificate) -> "SomeHostCertificateValidate":
        return CERT_TYPE_MAP[parent.cert_type](parent)

    @abc.abstractmethod
    def get_limits(self, msg: Message) -> Tuple[datetime, datetime]:
        """
        Implemented by subclasses. Receives the cert message with the initial field consumed
        :return: The not before and not after timestamps of the message (as aware datetimes)
        """
        ...

    @staticmethod
    def _as_datetime_tuple(a: int, b: int) -> Tuple[datetime, datetime]:
        return (
            datetime.fromtimestamp(a, timezone.utc),
            datetime.fromtimestamp(b, timezone.utc),
        )

    def check_renewal_required(self, limit: timedelta) -> "HostCertificateStatus":
        cert = self._parent.cert_data
        embedded_type = cert.get_string().decode("ascii")
        if embedded_type != self._parent.cert_type:
            raise RenewError("Certificate type mismatch in certificate")

        not_before, not_after = self.get_limits(cert)
        print(not_after)
        now = datetime.now(timezone.utc)
        return HostCertificateStatus(
            self._parent, now < not_before or (not_after - now) <= limit
        )


@register_for("ssh-rsa-cert-v01@openssh.com")
class RSACertificateValidate(SomeHostCertificateValidate):
    def get_limits(self, msg: Message) -> Tuple[datetime, datetime]:
        _nonce = msg.get_string()
        _e = msg.get_mpint()
        _n = msg.get_mpint()
        _serial = msg.get_int64()
        _key_type = msg.get_int()
        _key_id = msg.get_string()
        _principals = msg.get_string()
        return self._as_datetime_tuple(msg.get_int64(), msg.get_int64())


class DSSCertificateValidate(SomeHostCertificateValidate):
    def get_limits(self, msg: Message) -> Tuple[datetime, datetime]:
        _nonce = msg.get_string()
        _p = msg.get_mpint()
        _q = msg.get_mpint()
        _g = msg.get_mpint()
        _y = msg.get_mpint()
        _serial = msg.get_int64()
        _key_type = msg.get_int()
        _key_id = msg.get_string()
        _principals = msg.get_string()
        return self._as_datetime_tuple(msg.get_int64(), msg.get_int64())


@register_for(
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
)
class ECDSACertificateValidate(SomeHostCertificateValidate):
    def get_limits(self, msg: Message) -> Tuple[datetime, datetime]:
        _nonce = msg.get_string()
        _curve = msg.get_string()
        _public_key = msg.get_string()
        _serial = msg.get_int64()
        _key_type = msg.get_int()
        _key_id = msg.get_string()
        _principals = msg.get_string()
        return self._as_datetime_tuple(msg.get_int64(), msg.get_int64())


@register_for("ssh-ed25519-cert-v01@openssh.com")
class Ed25519CertificateValidate(SomeHostCertificateValidate):
    def get_limits(self, msg: Message) -> Tuple[datetime, datetime]:
        _nonce = msg.get_string()
        _pk = msg.get_string()
        _serial = msg.get_int64()
        _key_type = msg.get_int()
        _key_id = msg.get_string()
        _principals = msg.get_string()
        return self._as_datetime_tuple(msg.get_int64(), msg.get_int64())


__all__ = ["HostCertificate"]
