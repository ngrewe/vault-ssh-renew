from datetime import timedelta
import os
import sys
import traceback

import click
from environs import EnvError

from vault_ssh_renew.env import Config
from vault_ssh_renew.errors import RenewError
from vault_ssh_renew.cert import HostCertificate
from vault_ssh_renew.vault import VaultRenewer


def renew():
    try:
        config = Config()
    except EnvError as e:
        click.echo(click.style(str(e), fg="red"), err=True)
        sys.exit(1)
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
