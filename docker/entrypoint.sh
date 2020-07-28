#!/bin/sh -eu

/venv/bin/vault-ssh-renew
/usr/sbin/crond -f