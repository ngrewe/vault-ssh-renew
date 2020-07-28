# Vault SSH Renewal Tool

[![Build Status](https://dev.azure.com/glaux/update-broker/_apis/build/status/ngrewe.vault-ssh-renew?branchName=master)](https://dev.azure.com/glaux/update-broker/_build/latest?definitionId=6&branchName=master)
[![PyPI version](https://badge.fury.io/py/vault-ssh-renew.svg)](https://badge.fury.io/py/vault-ssh-renew)
[ ![Download](https://api.bintray.com/packages/glaux/production/vault-ssh-renew/images/download.svg) ](https://bintray.com/glaux/production/vault-ssh-renew/_latestVersion)

`vault-ssh-renew` automates the process of renewing SSH host certificates issued by
[HashiCorp Vault](https://www.vaultproject.io/). It will check whether a certificate
is installed on the host, and whether it expires in the near future. Only then will it
request Vault to issue a new certificate.

Please note that `vault-ssh-renew` does not take care of renewing the Vault token itself or of re-configuring your SSH server software to actually present the certificate. Please refer to the
[Vault documentation](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates#host-key-signing) on how to achieve this.

## Installation

### Pip

```sh
pip install vault-ssh-renew
```

### Debian/Ubuntu Packages

On Debian Buster, Ubuntu 18.04, and 20.04, you can install vault-ssh-renew from packages:

```sh
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv AF0E925C4504784BF4E0FFF0C90E4BD2B36E75B9
echo "deb https://dl.bintray.com/glaux/production $(lsb_release -s -c) main" | sudo tee -a /etc/apt/sources.list.d/vault-ssh-renew.list
sudo apt-get update
sudo apt-get install vault-ssh-renew
```
The package will also install a daily timer to run vault-ssh-renew. If you are installing interactively,
you will also be asked supply all the required configuration parameters, which will be written 
to `/etc/default/vault-ssh-renew` and can be edited there.

### Docker

You may also run the tool using a Docker container:

```
docker run -ti -v/etc/ssh:/etc/ssh \
    -e VAULT_TOKEN=**** \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_SSH_SIGN_PATH=ssh/sign/host \
    glaux/vault-ssh-renew
```

For every release, there also exists a corresponding tag suffixed with `.cron` (e.g.: `:latest.cron`) that
runs the tools as a periodic cron job.

## Configuration

Configuration can be achieved using the following environment variables.

| Variable                           | Data Type       | Meaning | Default |
|------------------------------------|-----------------|---------|---------|
| `VAULT_ADDR`                       | URL             | Address under which Vault can be reached. | http://127.0.0.1:8200 |
| `VAULT_TOKEN`                      | String          | Token for authentication against Vault. | |
| `VAULT_TOKEN_FILE`                 | String          | The path to read the Vault token from. | |
| `VAULT_SSH_HOST_KEY_PATH`          | String          | The path to the SSH public key. | `/etc/ssh/ssh_host_rsa_key.pub` |
| `VAULT SSH_HOST_CERT_PATH`         | String          | The path to the SSH host certificate. | `/etc/ssh/ssh_host_rsa_key-cert.pub` |
| `VAULT_SSH_SIGN_PATH`              | String          | The path to the signing endpoint, usually ⟨secret mountpoint⟩/sign/⟨role name⟩. |
| `VAULT_SSH_PRINCIPALS`             | List of Strings | A space separated list of principals to request in the certificate | Host's FQDN |
| `VAULT_SSH_RENEWAL_THRESHOLD_DAYS` | Integer         | When the certificate is valid for less then this many days, renew it. | 7 |


## Kubernetes Deployment

The directory `kubernetes/` in the source distribution contains a set of resources that can serve as a template to deploy vault-ssh-renew across your Kubernetes cluster. You'll need to:

* edit `secret.yaml` to supply your Vault token
* add the correct Vault address and signing path to `configmap.yaml`
* optionally change the version in `daemonset.yaml` to something other than `latest`

```sh
kubectl apply -f kubernetes/*.yaml
```