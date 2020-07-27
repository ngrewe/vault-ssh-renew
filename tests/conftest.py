import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pytest


TEST_FILES = pytest.mark.datafiles(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
)


@pytest.fixture(scope="function")
def public_key(datafiles, request) -> Path:
    return datafiles / request.param + ".pub"


@pytest.fixture(scope="function")
def certificate(datafiles, request) -> Path:
    return datafiles / request.param + "-cert.pub"


@pytest.fixture()
def mock_config(datafiles):
    class MockConfig:
        addr = urlparse("http://127.0.0.1:8200/")
        token = "mytoken"
        renewal_threshold_days = 7
        ssh_sign_path = "ssh/sign/host"
        ssh_principals = [
            "nowhere.example.com",
        ]
        ssh_host_key_path = datafiles / "rsa.pub"
        ssh_host_cert_path = datafiles / "rsa-cert.pub"
        on_renew_hook = "touch " + os.path.join(str(datafiles), "renewed")
        on_failure_hook = "touch " + os.path.join(str(datafiles), "failed")
        debug = False

        @staticmethod
        def exit(exit_code: int):
            pass

    return MockConfig()


@pytest.fixture(autouse=True)
def entrypoint_config(mocker, mock_config):
    return mocker.patch("vault_ssh_renew.cli.Config", return_value=mock_config)


@pytest.fixture
def success_renewal_mock(requests_mock, mock_config):
    requests_mock.post(
        urlunparse(mock_config.addr) + "/v1/" + mock_config.ssh_sign_path,
        json={"data": {"signed_key": "foo"}},
    )
    return requests_mock


@pytest.fixture
def no_permission_renewal_mock(requests_mock, mock_config):
    requests_mock.post(
        urlunparse(mock_config.addr) + "/v1/" + mock_config.ssh_sign_path,
        status_code=403,
        json={"errors": ["Not permitted"]},
    )
    return requests_mock
