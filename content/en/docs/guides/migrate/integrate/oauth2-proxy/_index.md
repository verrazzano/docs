---
title: "OAuth2 Proxy"
weight: 1
draft: false
---
This document shows you how to integrate OAuth2 Proxy with other OCNE components.

## Configure applications to be authenticated using oauth2-proxy

1. Assumptions from the installation of [dex]({{< relref "/docs/guides/migrate/install/dex/_index.md" >}}) and [oauth2-proxy]({{< relref "/docs/guides/migrate/install/oauth2-proxy/_index.md" >}}):

    * The load balancer address is using `nip.io`.
    * Insecure connections (http) are used for dex and oauth2-proxy.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ ADDRESS=$(kubectl get service -n ingress-nginx ingress-controller-ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}').nip.io
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


1. Test access to an application:

   The username and password for the OAuth2 Proxy login form can be viewed as follows:

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ echo "Login username is '${DEX_USER_EMAIL}'"
   $ echo "Login password is '${DEX_PASSWORD}'"
   ```
   </div>
   {{< /clipboard >}}
