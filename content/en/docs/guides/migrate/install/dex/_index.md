---
title: "Dex"
weight: 1
draft: false
---
This document shows you how to install dex on OCNE.

## Overview

The following is a guide of how to install dex, an identity provider that uses OpenID Connect for authenticating access to applications.

## Install dex using Helm

1. Add the dex Helm repository to the cluster:
   {{< clipboard >}}
   <div class="highlight">
   
   ```
   $ helm repo add dex https://charts.dexidp.io
   $ helm repo update
   ```
   </div>
   {{< /clipboard >}}


1. Setup configuration parameters:

   For the example in this guide: 

   * A static user and password will be configured instead of an actual identity provider.
   * The load balancer address needs to be known before the installation.

   {{< clipboard >}}
   <div class="highlight">
   
   ```
   $ DEX_USER_NAME=admin
   $ DEX_USER_EMAIL=admin@example.com
   $ DEX_PASSWORD=$(openssl rand -base64 10)
   $ DEX_PASSWORD_HASH=$(htpasswd -nbBC 10 "" ${DEX_PASSWORD} | tr -d ':\n' | sed 's/$2y/$2a/')
   $ DEX_UUID=$(uuidgen)
   $ ADDRESS=111.222.333.444
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
  frontend:
    dir: /srv/dex/web
    issuer: Verrazzano
    logoURL: theme/logo.svg
    theme: verrazzano
  issuer: http://dex.${ADDRESS}.nip.io/dex
  oauth2:
    passwordConnector: local
    skipApprovalScreen: true
  staticClients:
  - id: oauth2-proxy
    name: "OAuth2 Proxy"
    public: true
    redirectURIs:
    - http://oauth2-proxy.${ADDRESS}.nip.io/oauth2/callback
    secret: oauth2-proxy-secret
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
host: dex.${ADDRESS}.nip.io
image:
  repository: ghcr.io/verrazzano/dex
  tag: v2.37.0-20230911122845-caabc629
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
  - host: dex.${ADDRESS}.nip.io
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

1. foo


1. bar

