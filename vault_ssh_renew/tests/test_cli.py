import pytest

from vault_ssh_renew.cli import renew
from .conftest import TEST_FILES


@TEST_FILES
@pytest.mark.usefixtures("success_renewal_mock")
@pytest.mark.freeze_time("2020-08-23T12:00:00+0000")
def test_renews(datafiles, mock_config):
    renew()
    assert mock_config.ssh_host_cert_path.read_text(encoding="utf-8") == "foo"
    assert (datafiles / "renewed").exists()


@TEST_FILES
@pytest.mark.freeze_time("2020-07-22T23:00:00+0000")
def test_does_not_renew_if_recent(datafiles, success_renewal_mock):
    renew()
    assert not success_renewal_mock.called
    assert not (datafiles / "renewed").exists()


@TEST_FILES
@pytest.mark.usefixtures("success_renewal_mock")
@pytest.mark.freeze_time("2020-08-23T12:00:00+0000")
def test_calls_error_hook_on_cert_error(datafiles, mock_config, mocker):
    mock_config.ssh_host_cert_path = datafiles / "bad-cert.pub"
    exit_spy = mocker.spy(mock_config, "exit")
    renew()
    assert (datafiles / "failed").exists()
    exit_spy.assert_called_once_with(1)


@TEST_FILES
@pytest.mark.usefixtures("no_permission_renewal_mock")
@pytest.mark.freeze_time("2020-08-23T12:00:00+0000")
def test_calls_error_hook_on_vault_error(datafiles, mock_config, mocker):
    exit_spy = mocker.spy(mock_config, "exit")
    renew()
    assert (datafiles / "failed").exists()
    exit_spy.assert_called_once_with(1)
