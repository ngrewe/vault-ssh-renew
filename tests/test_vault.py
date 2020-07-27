from hamcrest import assert_that, has_entries, all_of, contains_string
import pytest
from requests import Request

from vault_ssh_renew.errors import RenewError
from vault_ssh_renew.vault import VaultRenewer


def test_successfully_renews(mock_config, success_renewal_mock):
    VaultRenewer.build(
        mock_config.addr,
        mock_config.token,
        mock_config.ssh_sign_path,
        "bar",
        mock_config.ssh_principals,
        mock_config.ssh_host_cert_path,
    ).renew().write_certificate()
    req: Request = success_renewal_mock.last_request
    assert req.headers["X-Vault-Token"] == mock_config.token
    assert_that(
        req.json(),
        has_entries(
            {
                "cert_type": "host",
                "public_key": "bar",
                "valid_principals": all_of(
                    *[
                        contains_string(principal)
                        for principal in mock_config.ssh_principals
                    ]
                ),
            }
        ),
    )
    assert mock_config.ssh_host_cert_path.read_text("utf-8") == "foo"


@pytest.mark.usefixtures("no_permission_renewal_mock")
def test_raises_on_error(mock_config):
    with pytest.raises(RenewError):
        VaultRenewer.build(
            mock_config.addr,
            mock_config.token,
            mock_config.ssh_sign_path,
            "bar",
            mock_config.ssh_principals,
            mock_config.ssh_host_cert_path,
        ).renew().write_certificate()
