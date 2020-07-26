import socket
from datetime import timedelta
import os
import traceback
from pathlib import Path
from urllib.parse import urlparse

import click

from vault_ssh_renew.config import Config
from vault_ssh_renew.errors import RenewError
from vault_ssh_renew.cert import HostCertificate
from vault_ssh_renew.util import URLParameterType
from vault_ssh_renew.vault import VaultRenewer

DEFAULT_VAULT_ADDR = "http://127.0.0.1:8200"


@click.command()
@click.argument(
    "ssh-host-key-path",
    envvar="VAULT_SSH_HOST_KEY_PATH",
    type=click.Path(),
    default=Path("/etc/ssh/ssh_host_rsa_key.pub"),
)
@click.argument(
    "ssh-host-cert-path",
    envvar="VAULT_SSH_HOST_CERT_PATH",
    type=click.Path(),
    default=Path("/etc/ssh/ssh_host_rsa_key-cert.pub"),
)
@click.option(
    "-a",
    "--vault-addr",
    envvar="VAULT_ADDR",
    type=URLParameterType(),
    default=urlparse(DEFAULT_VAULT_ADDR),
    help="Address under which vault can be reached.",
)
@click.option(
    "-t",
    "--vault-token",
    envvar="VAULT_TOKEN",
    help="Token for authentication against Vault.",
    required=True,
)
@click.option(
    "-p",
    "--ssh-sign-path",
    envvar="VAULT_SSH_SIGN_PATH",
    help="The path to the signing endpoint, usually <secret mountpoint>/sign/<role name>.",
    required=True,
)
@click.option(
    "--ssh-hostname",
    envvar="VAULT_SSH_HOSTNAME",
    help="The hostname to use as a principal, if not specified autodetection will be attempted.",
    default=lambda: socket.getfqdn(),
)
@click.option(
    "-w",
    "--renewal-threshold-days",
    envvar="VAULT_SSH_RENEWAL_THRESHOLD_DAYS",
    type=int,
    default=7,
    help="When the certificate is valid for less then this many days, renew it.",
    show_default=True,
)
@click.option(
    "--on-renew",
    envvar="VAULT_SSH_ON_RENEW",
    help="Hook script to execute when renewal succeeds.",
)
@click.option(
    "--on-failure",
    envvar="VAULT_SSH_ON_FAILURE",
    help="Hook script to execute when renewal fails.",
)
@click.option(
    "-d",
    "--debug",
    envvar="VAULT_SSH_DEBUG",
    is_flag=True,
    type=bool,
    help="Turn on debug output.",
    default=False,
)
def renew(**kwargs):
    """
    Renew the hosts SSH certificate using the specified Vault server. By default, it will
    read the RSA host key from /etc/ssh/ssh_host_rsa_key.pub and write the certificate to
    /etc/ssh/ssh_host_rsa_key-cert.pub. ECDSA and Ed25519 keys are also supported.

    All options can also be supplied using environment variables with a `VAULT_SSH_` prefix,
    except for the token and address options, which use the customary environment variables
    `VAULT_ADDR` and `VAULT_TOKEN`.
    """
    run_renew_workflow(Config(**kwargs))


def run_renew_workflow(config: Config):
    try:
        status = (
            HostCertificate.get(config.ssh_host_key_path, config.ssh_host_cert_path)
            .read()
            .check_renewal_required(timedelta(days=config.renewal_threshold_days))
        )
    except RenewError:
        click.echo(
            click.style("An error occurred when checking certificate status", fg="red"),
            err=True,
        )
        if config.debug:
            traceback.print_exc()
        if config.on_failure_hook:
            os.system(config.on_failure_hook)
        return config.exit(1)
    if not status.needs_renewal:
        click.echo(click.style("No renewal required", fg="green"))
        return
    try:
        VaultRenewer.build(
            config.addr,
            config.token,
            config.ssh_sign_path,
            status.public_key,
            config.ssh_hostname,
            config.ssh_host_cert_path,
        ).renew().write_certificate()
    except RenewError:
        click.echo(
            click.style("An error occurred when renewing the certificate", fg="red"),
            err=True,
        )
        if config.debug:
            traceback.print_exc()
        if config.on_failure_hook:
            os.system(config.on_failure_hook)
        return config.exit(1)
    click.echo(click.style("Certificate renewed", fg="green", bold=True))
    if config.on_renew_hook:
        os.system(config.on_renew_hook)


if __name__ == "__main__":
    renew()
