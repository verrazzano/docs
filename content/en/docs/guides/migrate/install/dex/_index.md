---
title: "Dex"
weight: 1
draft: false
---
This document shows you how to install [dex](https://dexidp.io/docs/), an identity provider that uses OpenID Connect for authenticating access to applications.

## Install dex using Helm

1. Add the dex Helm repository to the cluster.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ helm repo add dex https://charts.dexidp.io
   $ helm repo update
   ```
   </div>
   {{< /clipboard >}}


1. Set up configuration parameters.

   Assumptions for the example in this guide:

   * A static user and password will be configured instead of an actual identity provider.
   * The load balancer address must be known _before_ the installation.
   * The load balancer address uses `nip.io`.
   * Insecure connections (HTTP) are used for dex and oauth2-proxy.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ DEX_USER_NAME=admin
   $ DEX_USER_EMAIL=admin@example.com
   $ DEX_PASSWORD=$(openssl rand -base64 10)
   $ DEX_PASSWORD_HASH=$(htpasswd -nbBC 10 "" ${DEX_PASSWORD} | tr -d ':\n' | sed 's/$2y/$2a/')
   $ DEX_UUID=$(uuidgen)
   $ ADDRESS=$(kubectl get service -n ingress-nginx ingress-controller-ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}').nip.io
   $ OAUTH2_PROXY_SECRET=$(openssl rand -base64 10)
   $ DEX_IMAGE_REPO=ghcr.io/verrazzano/dex
   $ DEX_IMAGE_TAG=v2.37.0-20230911122845-caabc629
   ```
   </div>
   {{< /clipboard >}}


1. Generate a Helm override file.
{{< clipboard >}}
<div class="highlight">

```
$ cat > dex-overrides.yaml - <<EOF
config:
  enablePasswordDB: true
  issuer: http://dex.${ADDRESS}/dex
  oauth2:
    passwordConnector: local
    skipApprovalScreen: true
  staticClients:
  - id: oauth2-proxy
    name: "OAuth2 Proxy"
    public: true
    redirectURIs:
    - http://oauth2-proxy.${ADDRESS}/oauth2/callback
    secret: ${OAUTH2_PROXY_SECRET}
  staticPasswords:
  - email: "${DEX_USER_EMAIL}"
    hash: ${DEX_PASSWORD_HASH}
    userID: ${DEX_UUID}
    username: ${DEX_USER_NAME}
  storage:
    config:
      inCluster: true
    type: kubernetes
envVars:
- name: PASSWORD_DB_USERNAME_PROMPT
  value: Username
host: dex.${ADDRESS}
image:
  repository: ${DEX_IMAGE_REPO}
  tag: ${DEX_IMAGE_TAG}
ingress:
  annotations:
    external-dns.alpha.kubernetes.io/ttl: "60"
    kubernetes.io/tls-acme: "true"
    nginx.ingress.kubernetes.io/affinity: cookie
    nginx.ingress.kubernetes.io/proxy-buffer-size: 256k
    nginx.ingress.kubernetes.io/service-upstream: "true"
    nginx.ingress.kubernetes.io/session-cookie-conditional-samesite-none: "true"
    nginx.ingress.kubernetes.io/session-cookie-expires: "86400"
    nginx.ingress.kubernetes.io/session-cookie-max-age: "86400"
    nginx.ingress.kubernetes.io/session-cookie-name: dex
    nginx.ingress.kubernetes.io/session-cookie-samesite: Strict
    nginx.ingress.kubernetes.io/upstream-vhost: dex.dex.svc.cluster.local
  enabled: true
  className: nginx
  hosts:
  - host: dex.${ADDRESS}
    paths:
    - path: /dex
      pathType: ImplementationSpecific
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault
replicas: 1
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
  privileged: false
  runAsGroup: 0
  runAsNonRoot: true
  runAsUser: 1001
service:
  ports:
    http:
      port: 5556
EOF
```
</div>
{{< /clipboard >}}

1. Install dex.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ helm install dex dex/dex -n dex -f dex-overrides.yaml --create-namespace --version 0.15.3
   ```
   </div>
   {{< /clipboard >}}


1. Wait for the dex installation to complete.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl rollout status -n dex deployment dex -w
   ```
   </div>
   {{< /clipboard >}}
