# kube-impersonate-proxy

[![CI](https://github.com/vexxhost/kube-impersonate-proxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/vexxhost/kube-impersonate-proxy/actions/workflows/ci.yaml)
[![Image](https://github.com/vexxhost/kube-impersonate-proxy/actions/workflows/image.yaml/badge.svg)](https://github.com/vexxhost/kube-impersonate-proxy/actions/workflows/image.yaml)

`kube-impersonate-proxy` is an in-cluster reverse proxy for the Kubernetes API. It validates OIDC JWT bearer tokens and forwards requests to the API server using Kubernetes impersonation headers derived from token claims.

Highlights:

- OIDC JWT validation via issuer discovery/JWKS and audience (client ID)
- Claim-to-impersonation mapping for users and groups
- Upgrade support for `kubectl` (including `exec`, `attach`, and `port-forward`)
- Health endpoints: `/healthz` and `/readyz`

## Request flow

1. Client sends a request to the proxy with `Authorization: Bearer <JWT>`.
2. Proxy validates the JWT against the configured issuer (`--oidc-issuer-url`) and audience (`--oidc-client-id`).
3. Proxy strips the original `Authorization` header and sets impersonation headers based on token claims:
   - `Impersonate-User` from `--oidc-username-claim`
   - `Impersonate-Group` from `--oidc-groups-claim`
4. Proxy forwards the request to the Kubernetes API server using in-cluster configuration (ServiceAccount credentials).
5. Kubernetes authorizes the request as the impersonated user/group, provided the proxy ServiceAccount is allowed to impersonate those subjects.

## Requirements

- Runs inside Kubernetes (uses `rest.InClusterConfig`).
- Network access to the Kubernetes API server.
- Network access to the OIDC issuer (discovery + JWKS refresh).
- RBAC permissions for the proxy ServiceAccount to `impersonate` users/groups.

## Configuration

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--oidc-issuer-url` | yes | - | OIDC issuer URL. |
| `--oidc-client-id` | yes | - | Expected JWT audience (`aud`). |
| `--oidc-username-claim` | no | `email` | JWT claim mapped to `Impersonate-User`. |
| `--oidc-groups-claim` | no | `groups` | JWT claim mapped to `Impersonate-Group`. |
| `--listen-addr` | no | `:8080` | HTTP listen address. |

Notes:

- Claim values are used verbatim (no automatic prefixing).
- The binary exposes standard Kubernetes component logging flags (klog). Run `kube-impersonate-proxy --help` for the full flag set.

## Kubernetes deployment

Container image:

- `ghcr.io/vexxhost/kube-impersonate-proxy:<tag>`

Example manifests (adjust namespace, issuer URL, client ID, and image tag):

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kube-impersonate-proxy
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-impersonate-proxy
  namespace: kube-impersonate-proxy
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-impersonate-proxy
rules:
  - apiGroups: [""]
    resources: ["users", "groups"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-impersonate-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-impersonate-proxy
subjects:
  - kind: ServiceAccount
    name: kube-impersonate-proxy
    namespace: kube-impersonate-proxy
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-impersonate-proxy
  namespace: kube-impersonate-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: kube-impersonate-proxy
  template:
    metadata:
      labels:
        app: kube-impersonate-proxy
    spec:
      serviceAccountName: kube-impersonate-proxy
      containers:
        - name: kube-impersonate-proxy
          image: ghcr.io/vexxhost/kube-impersonate-proxy:<tag>
          args:
            - --listen-addr=:8080
            - --oidc-issuer-url=https://issuer.example.com/
            - --oidc-client-id=kubernetes
            - --oidc-username-claim=email
            - --oidc-groups-claim=groups
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
---
apiVersion: v1
kind: Service
metadata:
  name: kube-impersonate-proxy
  namespace: kube-impersonate-proxy
spec:
  selector:
    app: kube-impersonate-proxy
  ports:
    - name: http
      port: 8080
      targetPort: http
```

## Using the proxy

Point your Kubernetes client at the proxy endpoint and provide an OIDC JWT bearer token.

Example with `kubectl`:

```bash
export TOKEN="<your OIDC JWT>"
kubectl --server=https://kube-impersonate-proxy.example.com --token="$TOKEN" get ns
```

Local smoke test (port-forward + HTTP):

```bash
kubectl -n kube-impersonate-proxy port-forward svc/kube-impersonate-proxy 8080:8080
kubectl --server=http://127.0.0.1:8080 --token="$TOKEN" get ns
```

## Health endpoints

- `GET /healthz`: basic liveness check.
- `GET /readyz`: includes an OIDC health check.

## Security considerations

- The proxy does not implement TLS. Put it behind TLS termination (Ingress, Gateway API, or service mesh) and restrict network access.
- Impersonation is powerful. Keep the proxy ServiceAccount's `impersonate` permissions as narrow as practical (consider `resourceNames` restrictions).
- Choose stable claims for `--oidc-username-claim` (often `sub`) and ensure group membership claims are issued by a trusted IdP.
- The proxy logs the authenticated username and groups. Treat logs as potentially sensitive.

## Development

This repo uses `mise` for toolchain and common tasks:

```bash
mise run build
mise run test
mise run lint
```

Container build:

```bash
docker build -t kube-impersonate-proxy:local .
```

## License

Apache-2.0. See `LICENSE`.
