# syntax=docker/dockerfile:1
# hadolint global ignore=DL3008,DL3016
#
# The example services (examples/services/<name>/) as images: `wires serve`
# plus one vendor's CLI, running as the unprivileged user `wires` (uid
# 10001). One target per example; each <name>/compose.yml builds its own:
#
#   make image                         # once: the repo's wires image (wires:dev)
#   cd examples/services/github && docker compose build
#
# `wires` is copied from the repo's image (WIRES_IMAGE), not rebuilt here.
# Each vendor CLI is installed the way that vendor documents for Debian,
# cited at its stage; apt and npm packages are left unpinned (DL3008,
# DL3016) so a rebuild takes the vendor's current release.

ARG WIRES_IMAGE=wires:dev
ARG NODE_IMAGE=node:24-bookworm-slim

FROM ${WIRES_IMAGE} AS wires
FROM ${NODE_IMAGE} AS node

# What every example shares: wires, the wrappers' common.sh, the user, and
# its keystore mount point. Debian 12, as the repo's image is, for the same
# glibc.
FROM debian:bookworm-slim AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& groupadd --system --gid 10001 wires \
	&& useradd --system --uid 10001 --gid wires --home-dir /data --shell /usr/sbin/nologin wires \
	&& install -d -o wires -g wires -m 700 /data
COPY --from=wires /usr/local/bin/wires /usr/local/bin/wires
COPY common.sh /opt/wires-examples/services/common.sh
# The keystore: a named volume mounted here starts out owned by `wires`.
ENV WIRES_HOME=/data
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/wires"]
CMD ["serve", "/etc/wires-examples/host.json"]

# Node.js for the CLIs that ship on npm, from the official image (same
# Debian release).
FROM base AS base-node
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
	&& ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# --- Pattern A: federated -------------------------------------------------

# AWS CLI v2, the official installer:
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
FROM base AS aws
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl unzip \
	&& curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/awscliv2.zip \
	&& unzip -q /tmp/awscliv2.zip -d /tmp \
	&& /tmp/aws/install \
	&& rm -rf /tmp/aws /tmp/awscliv2.zip \
	&& apt-get purge -y curl unzip && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY aws/wrapper.sh /opt/wires-examples/services/aws/wrapper.sh
USER 10001:10001

# gcloud from Google's apt repository:
# https://cloud.google.com/sdk/docs/install#deb
FROM base AS gcp
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl gnupg \
	&& curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
	| gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
		>/etc/apt/sources.list.d/google-cloud-sdk.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends google-cloud-cli \
	&& apt-get purge -y curl gnupg && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY gcp/wrapper.sh /opt/wires-examples/services/gcp/wrapper.sh
USER 10001:10001

# kubectl, the release binary checked against its published SHA-256:
# https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
# KUBECTL_VERSION (e.g. v1.34.1) pins it; empty takes stable.txt.
FROM base AS k8s
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG KUBECTL_VERSION=
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& v="${KUBECTL_VERSION:-$(curl -fsSL https://dl.k8s.io/release/stable.txt)}" \
	&& url="https://dl.k8s.io/release/$v/bin/linux/$(dpkg --print-architecture)/kubectl" \
	&& curl -fsSL "$url" -o /tmp/kubectl \
	&& echo "$(curl -fsSL "$url.sha256")  /tmp/kubectl" | sha256sum --check \
	&& install -m 0755 /tmp/kubectl /usr/local/bin/kubectl \
	&& rm /tmp/kubectl \
	&& apt-get purge -y curl && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY k8s/wrapper.sh /opt/wires-examples/services/k8s/wrapper.sh
USER 10001:10001

# --- Pattern B: host-held -------------------------------------------------

# gh from GitHub's apt repository:
# https://github.com/cli/cli/blob/trunk/docs/install_linux.md
FROM base AS github
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& install -d -m 755 /etc/apt/keyrings \
	&& curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
		-o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
		>/etc/apt/sources.list.d/github-cli.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends gh \
	&& apt-get purge -y curl && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY github/wrapper.sh /opt/wires-examples/services/github/wrapper.sh
USER 10001:10001

# wrangler, installed into a project directory with npm, as Cloudflare
# recommends over a global install:
# https://developers.cloudflare.com/workers/wrangler/install-and-update/
FROM base-node AS cloudflare
ARG WRANGLER_VERSION=latest
WORKDIR /opt/wrangler
RUN npm init -y >/dev/null \
	&& npm install --no-fund --no-audit "wrangler@${WRANGLER_VERSION}" \
	&& npm cache clean --force \
	&& ln -s /opt/wrangler/node_modules/.bin/wrangler /usr/local/bin/wrangler
WORKDIR /data
COPY cloudflare/wrapper.sh /opt/wires-examples/services/cloudflare/wrapper.sh
USER 10001:10001

# The Vercel CLI, a global npm install: https://vercel.com/docs/cli
FROM base-node AS vercel
ARG VERCEL_VERSION=latest
RUN npm install -g --no-fund --no-audit "vercel@${VERCEL_VERSION}" \
	&& npm cache clean --force
COPY vercel/wrapper.sh /opt/wires-examples/services/vercel/wrapper.sh
USER 10001:10001

# The Supabase CLI's Linux release archive (Supabase lists the release
# assets as its Linux install; npm global installs are unsupported):
# https://supabase.com/docs/guides/local-development/cli/getting-started
# SUPABASE_RELEASE pins a tag (e.g. download/v2.40.7); the default is the
# latest release.
FROM base AS supabase
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG SUPABASE_RELEASE=latest/download
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& curl -fsSL "https://github.com/supabase/cli/releases/${SUPABASE_RELEASE}/supabase_linux_$(dpkg --print-architecture).tar.gz" \
	| tar -xz -C /usr/local/bin supabase \
	&& apt-get purge -y curl && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY supabase/wrapper.sh /opt/wires-examples/services/supabase/wrapper.sh
USER 10001:10001

# The Stripe CLI from Stripe's apt repository:
# https://docs.stripe.com/stripe-cli/install (Linux, apt)
FROM base AS stripe
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl gnupg \
	&& curl -fsSL https://packages.stripe.dev/api/security/keypair/stripe-cli-gpg/public \
	| gpg --dearmor -o /usr/share/keyrings/stripe.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/stripe.gpg] https://packages.stripe.dev/stripe-cli-debian-local stable main" \
		>/etc/apt/sources.list.d/stripe.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends stripe \
	&& apt-get purge -y curl gnupg && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*
COPY stripe/wrapper.sh /opt/wires-examples/services/stripe/wrapper.sh
USER 10001:10001

# --- Tests only -----------------------------------------------------------

# One example with .scripts/fixtures/stub-cli.sh standing in for its CLI,
# for .scripts/demo-example-services-docker.sh: SERVICE is the example, CLI
# the name the wrapper execs, and the build context `fixtures` the stub's
# directory.
FROM base AS stub
ARG SERVICE
ARG CLI
COPY ${SERVICE}/wrapper.sh /opt/wires-examples/services/${SERVICE}/wrapper.sh
# hadolint ignore=DL3022
COPY --from=fixtures stub-cli.sh /usr/local/bin/${CLI}
USER 10001:10001
