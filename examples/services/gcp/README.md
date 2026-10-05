# gcp: gcloud, as the person calling

Pattern A ([docs/examples.md](../../../docs/examples.md)): the host holds no
Google Cloud credential. Each call hands the caller's ID token to Workload
Identity Federation, which trades it for a short-lived token of the service
account their wires role maps to.

An agent gets `gcloud` with the `--format` and `--filter` it already knows,
and no Google Cloud key on its machine.

## Once, in Google Cloud

A pool, and a provider that trusts the IdP for the wires OAuth client ID:

```bash
gcloud iam workload-identity-pools create wires --location=global --display-name="wires callers"
gcloud iam workload-identity-pools providers create-oidc wires-idp \
  --location=global --workload-identity-pool=wires \
  --issuer-uri="https://idp.acme.com" --allowed-audiences="<wires client id>" \
  --attribute-mapping="google.subject=assertion.sub,attribute.email=assertion.email" \
  --attribute-condition="assertion.email.endsWith('@acme.com')"
```

One service account per wires role, which the pool's identities may
impersonate:

```bash
gcloud iam service-accounts create wires-readonly --project=acme-prod
gcloud projects add-iam-policy-binding acme-prod --role=roles/viewer \
  --member=serviceAccount:wires-readonly@acme-prod.iam.gserviceaccount.com
gcloud iam service-accounts add-iam-policy-binding \
  wires-readonly@acme-prod.iam.gserviceaccount.com --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/wires/*"
```

The last binding can name one person instead of the whole pool
(`…/workloadIdentityPools/wires/attribute.email/alice@acme.com`), so the
cloud checks the person as well as the role.

## Once, on the host

The host runs this example as a container: `wires serve` and `gcloud`
(Google's apt repository, [../Dockerfile](../Dockerfile)) as the
unprivileged user `wires`, with no port published, since wires dials out.
From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
$EDITOR gcp.roles host.json        # service accounts; the provider and project
docker compose build
docker compose run --rm gcp join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm gcp serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

There is no secret to install. In [host.json](host.json),
`GCP_WORKLOAD_PROVIDER` is the provider's resource name
(`projects/<number>/locations/global/workloadIdentityPools/wires/providers/wires-idp`)
and `CLOUDSDK_CORE_PROJECT` the default project; it and
[gcp.roles](gcp.roles) are mounted read-only, and `STATE_DIR`, where each
call's files go, is a tmpfs. The wrapper writes the call's credential configuration (an
`external_account` file whose `credential_source.file` is the call's token
file), runs `gcloud auth login --cred-file` into a `CLOUDSDK_CONFIG` of the
call's own, then the agent's command. Its default subcommands are `compute
storage logging projects run container sql functions artifacts`; never
`auth`, whose `print-access-token` would hand the token to the agent.

## Once, as the admin

```bash
wires service add gcp --description "gcloud as you: wires call gcp -- <gcloud args>" \
  --allow analyst --allow sre --host workbench
```

## What an agent runs

```bash
wires call gcp -- compute instances list --filter="status=RUNNING" --format="value(name,zone)"
wires call gcp -- logging read 'severity>=ERROR' --limit 20 --format="value(textPayload)"
wires call gcp -- run services list --format="json(metadata.name,status.url)"
```

## Limits

- **A real IdP.** Google's STS fetches the issuer's discovery document and
  keys, so `dev-mock-idp` can't stand in; `make demo-examples` stops at a
  stub `gcloud`.
- **Google as the IdP is not verified here.** The setup above is the
  documented one for an external OIDC IdP (Okta, Entra ID, Auth0, …). We
  found no statement either way on `https://accounts.google.com` as a
  Workload Identity Federation issuer.
- **The credentials live inside one call**, and fail once the sign-in
  expires (about an hour with Google) until `wires login`.
- **No session name.** Google's audit logs name the federated principal by
  `google.subject` (here the IdP's `sub`); map it to `assertion.email` to see
  the email there, if your IdP never reuses one.
- **Google Cloud trusts the IdP, not wires**: see [docs/examples.md](../../../docs/examples.md#limits).

## Sources

- Pool, provider, impersonation, `create-cred-config`, `gcloud auth login --cred-file`: https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers
- `google.subject` (≤127 characters, in Cloud Logging), attribute conditions: https://docs.cloud.google.com/iam/docs/workload-identity-federation
- The `external_account` file format: https://google.aip.dev/auth/4117
- `CLOUDSDK_CONFIG` and `CLOUDSDK_<SECTION>_<PROPERTY>`: https://cloud.google.com/sdk/gcloud/reference/config, https://docs.cloud.google.com/sdk/gcloud/reference/topic/configurations
