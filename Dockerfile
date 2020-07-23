FROM python:3.8-alpine AS builder
ARG POETRY_VERSION=1.0.3
RUN apk add --no-cache gcc make libffi-dev musl-dev openssl-dev \
    && pip install poetry==${POETRY_VERSION} virtualenv \
    && mkdir /src && virtualenv /venv
ADD . /src
WORKDIR /src
RUN . /venv/bin/activate && poetry install --no-root --no-dev && poetry build && pip install dist/vault_ssh_renew-*.whl
FROM python:3.8-alpine
RUN apk add --no-cache openssl libffi && mkdir -p /etc/ssh
COPY --from=builder /venv /venv
VOLUME [ "/etc/ssh" ]
ENTRYPOINT [ "/venv/bin/vault-ssh-renew" ]