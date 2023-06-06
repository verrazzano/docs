---
title: Get Console Credentials
description: "Get the credentials to access the consoles that Verrazzano installs"
weight: 3
draft: false
---

### Consoles accessed by the same user name

- Grafana
- Prometheus
- OpenSearch Dashboards
- OpenSearch
- Kiali
- Jaeger
- Thanos Query

**User**: `verrazzano`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get secret \
        --namespace verrazzano-system verrazzano \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}

### The Argo CD console

You can log in to the Argo CD console using the `verrazzano` user configured in Keycloak or with the local `admin` user for Argo CD.
To log in with Keycloak, select the `Log in with Keycloak` link or enter the local user credentials to log in as a local user.

**Local Admin User**: `admin`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl -n argocd get secret \
        argocd-initial-admin-secret \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}

**Keycloak User**: `verrazzano`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get secret \
        --namespace verrazzano-system verrazzano \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}

### The Keycloak admin console

**User**: `keycloakadmin`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get secret \
        --namespace keycloak keycloak-http \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}

### The Rancher console

You can log in to the Rancher console using the `verrazzano` user configured in Keycloak or with the local `admin` user for Rancher.
To log in with Keycloak, select the `Log in with Keycloak` link or select the `Use a local user` link to log in with the local user.

**Local Admin User**: `admin`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get secret \
        --namespace cattle-system rancher-admin-secret \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}

**Keycloak User**: `verrazzano`

To get the password:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get secret \
        --namespace verrazzano-system verrazzano \
        -o jsonpath={.data.password} | base64 \
        --decode; echo

</div>
{{< /clipboard >}}
