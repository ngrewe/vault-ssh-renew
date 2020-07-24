from datetime import timedelta
from pathlib import Path

import pytest

from vault_ssh_renew.cert import HostCertificate
from vault_ssh_renew.errors import RenewError
from .conftest import TEST_FILES


@TEST_FILES
@pytest.mark.parametrize(
    "public_key", ["rsa", "ecdsa", "ed25519"], indirect=["public_key"]
)
def test_requires_renewal_for_no_cert(datafiles: Path, public_key: Path):
    target_cert = datafiles / "my-cert.pub"
    status = (
        HostCertificate.get(public_key, target_cert)
        .read()
        .check_renewal_required(timedelta(days=0))
    )
    assert status.needs_renewal is True
    assert len(status.public_key) > 0


@TEST_FILES
@pytest.mark.parametrize(
    "public_key,certificate",
    [(x, x) for x in ["rsa", "ecdsa", "ed25519"]],
    indirect=["public_key", "certificate"],
)
@pytest.mark.freeze_time("2020-07-22T23:00:00+0000")
def test_requires_no_renewal_for_recent_certs(public_key: Path, certificate: Path):
    status = (
        HostCertificate.get(public_key, certificate)
        .read()
        .check_renewal_required(timedelta(days=1))
    )
    assert status.needs_renewal is False


@TEST_FILES
@pytest.mark.parametrize(
    "public_key,certificate",
    [(x, x) for x in ["rsa", "ecdsa", "ed25519"]],
    indirect=["public_key", "certificate"],
)
@pytest.mark.freeze_time("2020-08-23T12:00:00+0000")
def test_requires_renewal_for_soon_expiring_certs(public_key: Path, certificate: Path):
    # Certifiates in the test set expire on the evening of 2020-08-23, which is less than a day
    status = (
        HostCertificate.get(public_key, certificate)
        .read()
        .check_renewal_required(timedelta(days=1))
    )
    assert status.needs_renewal is True


@TEST_FILES
@pytest.mark.parametrize(
    "public_key,certificate",
    [(x, x) for x in ["rsa", "ecdsa", "ed25519"]],
    indirect=["public_key", "certificate"],
)
@pytest.mark.freeze_time("2020-08-23T12:00:00+0000")
def test_requires_renewal_for_expired_certs(public_key: Path, certificate: Path):
    # Certificates in the test set have expired on the evening of 2020-08-23
    status = (
        HostCertificate.get(public_key, certificate)
        .read()
        .check_renewal_required(timedelta(days=1))
    )
    assert status.needs_renewal is True


@TEST_FILES
@pytest.mark.parametrize(
    "public_key,certificate",
    [(x, x) for x in ["rsa", "ecdsa", "ed25519"]],
    indirect=["public_key", "certificate"],
)
@pytest.mark.freeze_time("2020-07-21T12:00:00+0000")
def test_requires_renewal_not_yet_valid_certs(public_key: Path, certificate: Path):
    status = (
        HostCertificate.get(public_key, certificate)
        .read()
        .check_renewal_required(timedelta(days=1))
    )
    assert status.needs_renewal is True


@TEST_FILES
def test_rejects_cert_with_mismatching_data_between_header_and_payload(datafiles: Path):
    with pytest.raises(RenewError):
        HostCertificate.get(
            datafiles / "rsa.pub", datafiles / "bad-cert.pub"
        ).read().check_renewal_required(timedelta(days=1))
