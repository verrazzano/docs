---
title: "OAuth2 Proxy"
weight: 1
draft: false
---
This document shows you how to install [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/), a reverse proxy that provides authentication with identity providers.

## Install OAuth2 Proxy using Helm

1. Add the OAuth2 Proxy repository to the cluster.
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add oauth2-proxy https://oauth2-proxy.github.io/manifests
$ helm repo update
```
</div>
{{< /clipboard >}}

1. Set up configuration parameters.

   Assumptions for the example in this guide:

    * Dex is configured as the identity provider using a static user and password.
    * The load balancer address must be known _before_ the installation.
    * The load balancer address uses `nip.io`.
    * The value for OAUTH2_PROXY_SECRET must be the same value used when [dex]({{< relref "/docs/guides/migrate/install/dex/_index.md" >}}) was installed.
    * Insecure connections (HTTP) are used for dex and oauth2-proxy.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ ADDRESS=$(kubectl get service -n ingress-nginx ingress-controller-ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}').nip.io
   $ OAUTH2_COOKIE_SECRET=$(openssl rand -hex 16)
   ```
   </div>
   {{< /clipboard >}}


1. Generate a Helm override file.
   {{< clipboard >}}
<div class="highlight">

```
$ cat > oauth2-proxy-overrides.yaml - <<EOF
namespaceOverride: oauth2-proxy

ingress:
  enabled: true
  className: nginx
  hosts:
  - oauth2-proxy.${ADDRESS}

config:
  clientID: oauth2-proxy
  clientSecret: "${OAUTH2_PROXY_SECRET}"
  cookieSecret: "${OAUTH2_COOKIE_SECRET}"
  configFile: |-
    cookie_domains=".${ADDRESS}"
    whitelist_domains=[".${ADDRESS}"]
    email_domains=["example.com"]
    cookie_secure="false"
    redirect_url="http://oauth2-proxy.${ADDRESS}/oauth2/callback"
    upstreams = [ "file:///dev/null" ]

    set_xauthrequest = true
    provider="oidc"
    oidc_issuer_url="http://dex.${ADDRESS}/dex"
EOF
```
</div>
{{< /clipboard >}}

1. Install oauth2-proxy.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ helm install -n oauth2-proxy oauth2-proxy oauth2-proxy/oauth2-proxy -f oauth2-proxy-overrides.yaml --create-namespace --version 6.24.1
   ```
   </div>
   {{< /clipboard >}}


1. Wait for the installation of oauth2-proxy to complete.
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl rollout status -n oauth2-proxy deployment oauth2-proxy -w
   ```
   </div>
   {{< /clipboard >}}
