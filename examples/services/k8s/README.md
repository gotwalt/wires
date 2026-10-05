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

```bash
sudo cp -R examples/services /opt/wires-examples/
sudo install -d -o wires -m 700 /var/lib/wires-examples/k8s
printf 'analyst analytics\nsre default\n' | sudo tee /etc/wires-examples/k8s.roles
sudo cp cluster-ca.crt /etc/wires-examples/k8s-ca.crt
```

The role map gives each wires role a default namespace: a convenience, not
a boundary, since `--namespace` overrides it and RBAC decides. Merge
[host.json](host.json)'s `k8s` entry into the host's `host.json`
(`K8S_SERVER`, `K8S_CA_FILE`). `kubectl` must be on `serve`'s `PATH`. The
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
