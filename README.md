# JFrog Token Exchanger

[![CI](https://github.com/richardmsong/jfrog-token-exchanger/actions/workflows/ci.yml/badge.svg)](https://github.com/richardmsong/jfrog-token-exchanger/actions/workflows/ci.yml)

A Kubernetes controller that automatically manages JFrog registry credentials by exchanging Kubernetes ServiceAccount tokens for JFrog access tokens using OIDC token exchange.

## Description

JFrog Token Exchanger solves the problem of managing JFrog registry credentials in Kubernetes by:

- **Automating token exchange**: Converts Kubernetes ServiceAccount tokens into JFrog access tokens via OIDC token exchange (RFC 8693)
- **Managing secrets automatically**: Creates and maintains Docker config secrets with valid JFrog credentials
- **Token lifecycle management**: Automatically renews tokens before expiry to prevent authentication failures
- **Simplified integration**: Eliminates the need for manual credential rotation and management

## How It Works

1. Annotate a ServiceAccount with `jfrog.io/token: enabled`
2. The controller detects the annotation and requests a K8s token via the TokenRequest API
3. The controller exchanges the K8s token with JFrog's OIDC endpoint for an access token
4. A `dockerconfigjson` secret is created with the JFrog credentials
5. The secret is attached as an `imagePullSecret` to the ServiceAccount
6. Pods using that ServiceAccount automatically get JFrog registry access
7. The controller monitors token expiry and refreshes tokens automatically

## Getting Started

You'll need a Kubernetes cluster to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.

### Prerequisites

- Kubernetes cluster (v1.27+)
- JFrog instance with OIDC token exchange configured
  - **Don't have a JFrog instance?** You can [provision a free trial of JFrog Artifactory](https://jfrog.com/start-free/) to test this controller
- OIDC provider configured in JFrog that trusts your Kubernetes cluster's ServiceAccount tokens

### Configuration

The controller requires the following environment variables or configuration:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `JTE_JFROG_URL` | Yes | Base URL of your JFrog instance | `https://mycompany.jfrog.io` |
| `JTE_JFROG_REGISTRY` | Yes | Registry hostname for docker config | `mycompany.jfrog.io` |
| `JTE_PROVIDER_NAME` | Conditional* | OIDC provider name configured in JFrog | `my-k8s-cluster` |
| `JTE_CLUSTER_NAME_RESOLUTION_MODE` | Conditional* | Auto-detect the provider identity from the environment. Supported modes: `oidc-issuer` (recommended), `azure` (deprecated) | `oidc-issuer` |

\* Either `JTE_PROVIDER_NAME` or `JTE_CLUSTER_NAME_RESOLUTION_MODE` must be set.

#### OIDC Issuer-Based Resolution (recommended, works on any cloud)

The controller can automatically derive a provider identity from the Kubernetes service account token's `iss` (issuer) claim, with no cloud-specific logic. Every Kubernetes cluster with a configured service-account-token issuer stamps that issuer into every SA token — this is standard OIDC/Kubernetes behavior, not specific to any one provider. For example:

- AKS: `iss: https://<region>.oic.prod-aks.azure.com/<tenant-id>/<cluster-id>/`
- EKS: `iss: https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>`

**How it works:**
- Set `JTE_CLUSTER_NAME_RESOLUTION_MODE=oidc-issuer`
- The controller reads the service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Decodes the JWT and extracts the `iss` claim verbatim
- Uses the issuer URL as the opaque provider name for JFrog OIDC token exchange — the issuer is the actual trust anchor Artifactory validates the token's signature against, so this is the protocol-correct value to key the provider registry on

**Example deployment (AKS or EKS):**
```yaml
env:
  - name: JTE_JFROG_URL
    value: "https://mycompany.jfrog.io"
  - name: JTE_JFROG_REGISTRY
    value: "mycompany.jfrog.io"
  - name: JTE_CLUSTER_NAME_RESOLUTION_MODE
    value: "oidc-issuer"
```

**Important:** The resolved value is an opaque issuer URL, not a friendly cluster name. **You must configure your JFrog Artifactory OIDC provider name to match the issuer URL exactly.** Use Artifactory's OIDC Identity Provider **Description** field to attach a human-readable cluster label — the provider name and the description don't need to match.

#### Azure Kubernetes Service (AKS) legacy mode (deprecated)

> **Deprecated:** `azure` mode is deprecated in favor of `oidc-issuer` above, which works identically on AKS, EKS, and any other OIDC-compliant cluster. `azure` continues to work for now but will be removed in a future major version. Existing deployments should migrate to `oidc-issuer` and re-register their JFrog OIDC Identity Provider under the new issuer-derived value, since the resolved provider name changes.

Prior to `oidc-issuer`, the controller could automatically detect an AKS cluster's friendly name from its default token audience.

**How it works:**
- Set `JTE_CLUSTER_NAME_RESOLUTION_MODE=azure`
- The controller reads the service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Decodes the JWT token and extracts the cluster name from the audience claim
- The audience claim format: `https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io`
- Uses the extracted cluster name as the provider name for JFrog OIDC token exchange

**Example AKS deployment (legacy):**
```yaml
env:
  - name: JTE_JFROG_URL
    value: "https://mycompany.jfrog.io"
  - name: JTE_JFROG_REGISTRY
    value: "mycompany.jfrog.io"
  - name: JTE_CLUSTER_NAME_RESOLUTION_MODE
    value: "azure"
```

**Important:** The cluster name extracted will match your AKS cluster's resource name. **You must configure your JFrog Artifactory OIDC provider name to match your AKS cluster name exactly.** For example, if your AKS cluster is named `my-prod-cluster`, your JFrog OIDC provider must also be named `my-prod-cluster`.

### Running on the cluster

1. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/jfrog-token-exchanger:tag
```

2. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/jfrog-token-exchanger:tag
```

### Usage

To enable automatic JFrog token management for a ServiceAccount, add the `jfrog.io/token: enabled` annotation:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: default
  annotations:
    jfrog.io/token: enabled
```

The controller will automatically:
- Create a secret named `<serviceaccount-name>-jfrog-token`
- Attach it to the ServiceAccount's `imagePullSecrets`
- Refresh the token before it expires

### Undeploy controller

UnDeploy the controller from the cluster:

```sh
make undeploy
```

## Development

### Test It Out

Run your controller locally (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

### Running Tests

```sh
make test
```

### How it works

This project follows the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) using [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

The controller watches ServiceAccount resources and reconciles when:
- A ServiceAccount is created/updated with the `jfrog.io/token: enabled` annotation
- A token is approaching expiry and needs renewal

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
