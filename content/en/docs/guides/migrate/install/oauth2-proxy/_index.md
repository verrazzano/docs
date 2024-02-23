---
title: "OAuth2 Proxy"
weight: 1
draft: false
---
This document shows you how to install OAuth2 Proxy on OCNE.

## Overview

The following is a guide of how to install OAuth2 Proxy, a reverse proxy that provides authentication with identity providers.

## Install OAuth2 Proxy using Helm

1. Add the OAuth2 Proxy repository to the cluster:
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add oauth2-proxy https://oauth2-proxy.github.io/manifests
$ helm repo update
```
</div>
{{< /clipboard >}}

1. Setup configuration parameters:

   For the example in this guide:

    * Dex is configured as the identity provider using a static user and password.
    * The load balancer address needs to be known before the installation.
    * Insecure connections (http) are used for dex and oauth2-proxy.
    * The oauth2-login screen is configured to use the Verrazzano theme.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ ADDRESS=111.222.333.444.nip.io
   $ OAUTH2_CLIENT_SECRET=$(openssl rand -base64 10)
   $ OAUTH2_COOKIE_SECRET=$(openssl rand -base64 32)
   ```
   </div>
   {{< /clipboard >}}

1. Generate a Helm override file.
   {{< clipboard >}}
<div class="highlight">

```
cat > oauth2-proxy-overrides.yaml - <<EOF
namespaceOverride: oauth2-proxy

ingress:
  enabled: true
  className: nginx
  hosts:
  - oauth2-proxy.${ADDRESS}

config:
  clientID: oauth2-proxy
  clientSecret: "${OAUTH2_CLIENT_SECRET}"
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

1. Install oauth2-proxy:
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ helm install -n oauth2-proxy oauth2-proxy oauth2-proxy/oauth2-proxy -f oauth2-proxy-overrides.yaml --create-namespace --version 6.24.1
   ```
   </div>
   {{< /clipboard >}}


1. Wait for the installation of oauth2-proxy to complete:
   {{< clipboard >}}
   <div class="highlight">

   ```
   $ kubectl rollout status -n oauth2-proxy deployment oauth2-proxy -w
   ```
   </div>
   {{< /clipboard >}}


1. Configure applications to be authenticated using oauth2-proxy:

   Add the following annotations to the ingresses of applications that will be authorized and authenticated using oauth2-proxy:
   * nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-User,X-Auth-Request-Email
   * nginx.ingress.kubernetes.io/auth-signin: http://oauth2-proxy.${ADDRESS}.nip.io/oauth2/start
   * nginx.ingress.kubernetes.io/auth-url: http://oauth2-proxy.oauth2-proxy.svc.cluster.local/oauth2/auth

   <br>For example:

   {{< clipboard >}}
   <div class="highlight">
   
   ```
   $ cat > ingress.yaml - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: example
     annotations:
       nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-User,X-Auth-Request-Email
       nginx.ingress.kubernetes.io/auth-signin: http://oauth2-proxy.${ADDRESS}.nip.io/oauth2/start
       nginx.ingress.kubernetes.io/auth-url: http://oauth2-proxy.oauth2-proxy.svc.cluster.local/oauth2/auth
   spec:
     ingressClassName: nginx
     rules:
       - host: example.${ADDRESS}.nip.io
         http:
           paths:
             - pathType: Prefix
               backend:
                 service:
                   name: example
                   port:
                     number: 8080
               path: /example
   EOF
   ```
   </div>
   {{< /clipboard >}}