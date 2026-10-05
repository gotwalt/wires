# aws: the AWS CLI, as the person calling

Pattern A ([docs/examples.md](../../../docs/examples.md)): the host holds no
AWS credential. Each call hands the caller's ID token to AWS STS
(`AssumeRoleWithWebIdentity`), assumes the IAM role their wires role maps
to, and names the session after their email, so CloudTrail shows
`assumed-role/wires-readonly/alice@acme.com`.

An agent gets `aws` with the `--query` and `--output` it already knows, and
no AWS key on its machine.

## Once, in AWS

With Google as the IdP, AWS already trusts `accounts.google.com`; skip the
first command. For any other OIDC IdP, register it with the wires OAuth
client ID as the audience:

```bash
aws iam create-open-id-connect-provider \
  --url https://idp.acme.com --client-id-list <wires client id>
```

One role per wires role. The trust policy for Google (another IdP uses its
provider ARN as `Federated` and `idp.acme.com:aud` as the key):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "accounts.google.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "accounts.google.com:aud": "<wires client id>" },
      "StringLike": { "accounts.google.com:email": "*@acme.com" }
    }
  }]
}
```

```bash
aws iam create-role --role-name wires-readonly --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name wires-readonly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

## Once, on the host

The host runs this example as a container: `wires serve` and the AWS CLI v2
(AWS's own installer, [../Dockerfile](../Dockerfile)) as the unprivileged
user `wires`, with no port published, since wires dials out. From this
directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
$EDITOR aws.roles                  # each wires role's IAM role ARN
docker compose build
docker compose run --rm aws join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm aws serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

There is no secret to install. [host.json](host.json) (`AWS_DEFAULT_REGION`
is yours to set) and [aws.roles](aws.roles) are mounted read-only;
`STATE_DIR`, where each call's token file goes, is a tmpfs, so tokens never
reach a disk. `ALLOW_COMMANDS` in `host.json` overrides the wrapper's
default subcommands (`sts s3 s3api ec2 logs cloudwatch lambda ecs dynamodb
cloudformation`; never `configure`, whose `export-credentials` prints the
session's keys).

## Once, as the admin

```bash
wires service add aws --description "AWS CLI as you: wires call aws -- <aws args>" \
  --allow analyst --allow sre --host workbench
```

## What an agent runs

```bash
wires call aws -- sts get-caller-identity --query Arn --output text
wires call aws -- ec2 describe-instances --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType]' --output text
wires call aws -- logs filter-log-events --log-group-name /app/api --filter-pattern ERROR \
  --max-items 20 --query 'events[].message' --output text
```

## Limits

- **A real IdP.** STS fetches the issuer's discovery document and keys from
  the internet, so `dev-mock-idp` can't stand in; the hermetic test
  (`make demo-examples`) stops at a stub `aws`.
- **The credentials live inside one call.** Each call exchanges the token
  again (`HOME` is the call's own directory, so nothing is cached between
  people), and once the sign-in expires (about an hour with Google) the
  exchange fails until `wires login`.
- **The email reaches the trust policy, not the session.** AWS offers
  `email` as a condition key when the role is assumed but not afterwards, so
  what each person may do comes from the wires role → IAM role map.
- **AWS trusts the IdP, not wires**: see [docs/examples.md](../../../docs/examples.md#limits).

## Sources

- The CLI's web-identity variables: https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html (`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME`, `AWS_EC2_METADATA_DISABLED`)
- `AssumeRoleWithWebIdentity` (session name: 2–64 of `[\w+=,.@-]`, shown in CloudTrail; one hour by default): https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- Google is built in; the trust policy: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
- Other IdPs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- Condition keys (`aud`, `email`, `sub`; `email` not in session): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif
