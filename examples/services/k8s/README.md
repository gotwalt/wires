# k8s: kubectl, as the person calling

Pattern A ([docs/examples.md](../../../docs/examples.md)): the host holds no
cluster credential. An API server that trusts the IdP takes the caller's ID
token as its bearer token, so Kubernetes RBAC and the API server's audit
log see the person's own email as the user name. Nothing is exchanged.

An agent gets `kubectl` with the `-o jsonpath` and `--field-selector` it
already knows, and no kubeconfig on its machine.

## Once, on the cluster

The API server trusts the IdP for the wires OAuth client ID, with the email
as the user name (`--authentication-config=/etc/kubernetes/auth.yaml`):

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://accounts.google.com
    audiences:
    - <wires client id>
  claimMappings:
    username:
      claim: email
      prefix: ""
```

With `claim: email` the API server also requires `email_verified`. RBAC per
person:

```bash
kubectl create rolebinding alice-view --clusterrole=view \
  --user=alice@acme.com --namespace=analytics
```

Managed clusters (GKE, EKS, AKS) configure an external OIDC issuer their
own way; this example doesn't cover them.

## Once, on the host

The host runs this example as a container: `wires serve` and `kubectl`
(the release binary, checked against its SHA-256,
[../Dockerfile](../Dockerfile)) as the unprivileged user `wires`, with no
port published, since wires dials out. From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
cp cluster-ca.crt k8s-ca.crt       # the API server's CA certificate
$EDITOR k8s.roles host.json        # namespaces; K8S_SERVER
docker compose build
docker compose run --rm k8s join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm k8s serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

There is no secret to install. [k8s.roles](k8s.roles) gives each wires
role a default namespace: a convenience, not a boundary, since
`--namespace` overrides it and RBAC decides. It, [host.json](host.json)
and the CA certificate are mounted read-only; `STATE_DIR` is a tmpfs. The
wrapper writes a kubeconfig for the call whose `tokenFile` is the call's
token file, which keeps the token out of `kubectl`'s argv. Its default
subcommands are `get describe logs top events explain api-resources auth
rollout`; not `exec`, `cp`, `port-forward` or `proxy`.

## Once, as the admin

```bash
wires service add k8s --description "kubectl as you: wires call k8s -- <kubectl args>" \
  --allow analyst --allow sre --host workbench
```

## What an agent runs

```bash
wires call k8s -- get pods --field-selector=status.phase!=Running \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
wires call k8s -- logs deploy/api --since=10m --tail=50
wires call k8s -- get events --field-selector type=Warning \
  -o custom-columns=REASON:.reason,OBJECT:.involvedObject.name
```

## Limits

- **A real IdP.** The API server fetches the issuer's discovery document;
  `make demo-examples` stops at a stub `kubectl`.
- **The token lasts as long as the sign-in** (about an hour with Google);
  after that the API server refuses it until `wires login`.
- **The cluster trusts the IdP, not wires**: see [docs/examples.md](../../../docs/examples.md#limits).
  Keep the API server reachable from the host's network only.

## Sources

- OIDC tokens, `--token`, `AuthenticationConfiguration` (`claim: email` implies `email_verified`): https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- kubeconfig `tokenFile`: https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
