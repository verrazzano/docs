---
title: Access Verrazzano
description: "Information and tools to support operating Verrazzano"
weight: 4
draft: false
aliases:
  - /docs/operations
---

## Get the consoles URLs

Verrazzano installs several consoles. The endpoints for an installation are stored in the `Status` field of the
installed Verrazzano Custom Resource.

You can access the installation endpoints using the [Verrazzano CLI]({{< relref "/docs/setup/install" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/):

- [Verrazzano CLI](#verrazzano-cli)
- [kubectl](#kubectl)

### Verrazzano CLI

You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:

```shell
$ vz status
```

The resulting output is similar to the following:

```shell
Verrazzano Status
  Name: verrazzano
  Namespace: default
  Version: 1.5.0
  State: Ready
  Profile: dev
  Available Components: 24/24
  Access Endpoints:
    argoCDUrl: https://argocd.default.172.18.0.231.nip.io
    consoleUrl: https://verrazzano.default.172.18.0.231.nip.io
    grafanaUrl: https://grafana.vmi.system.default.172.18.0.231.nip.io
    jaegerURL: https://jaeger.default.172.18.0.231.nip.io
    keyCloakUrl: https://keycloak.default.172.18.0.231.nip.io
    kialiUrl: https://kiali.vmi.system.default.172.18.0.231.nip.io
    openSearchDashboardsUrl: https://osd.vmi.system.default.172.18.0.231.nip.io
    openSearchUrl: https://opensearch.vmi.system.default.172.18.0.231.nip.io
    prometheusUrl: https://prometheus.vmi.system.default.172.18.0.231.nip.io
    rancherUrl: https://rancher.default.172.18.0.231.nip.io
    thanosQueryUrl: https://thanos-query.default.172.18.0.231.nip.io
```

### kubectl

You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:
{{< clipboard >}}

```shell
$ kubectl get vz -o yaml
```
{{< /clipboard >}}



The resulting output is similar to the following (abbreviated to show only the relevant portions):

{{< clipboard >}}
<div class="highlight">

```
  ...
  status:
    conditions:
    - lastTransitionTime: "2021-06-30T03:10:00Z"
      message: Verrazzano install in progress
      status: "True"
      type: InstallStarted
    - lastTransitionTime: "2021-06-30T03:18:33Z"
      message: Verrazzano install completed successfully
      status: "True"
      type: InstallComplete
    instance:
      argoCDUrl: https://argocd.default.172.18.0.231.nip.io
      consoleUrl: https://verrazzano.default.11.22.33.44.nip.io
      grafanaUrl: https://grafana.vmi.system.default.11.22.33.44.nip.io
      keyCloakUrl: https://keycloak.default.11.22.33.44.nip.io
      kialiUrl: https://kiali.vmi.system.default.11.22.33.44.nip.io
      opensearchDashboardsUrl: https://opensearchDashboards.vmi.system.default.11.22.33.44.nip.io
      opensearchUrl: https://opensearch.vmi.system.default.11.22.33.44.nip.io
      prometheusUrl: https://prometheus.vmi.system.default.11.22.33.44.nip.io
      rancherUrl: https://rancher.default.11.22.33.44.nip.io
      thanosQueryUrl: https://thanos-query.default.172.18.0.231.nip.io
```
</div>
{{< /clipboard >}}


If you have `jq` installed, then you can use the following command to get the instance URLs more directly.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vz -o jsonpath="{.items[].status.instance}" | jq .
```

</div>
{{< /clipboard >}}

The following is an example of the output:

```
{
"argoCDUrl": https://argocd.default.172.18.0.231.nip.io
"consoleUrl": "https://verrazzano.default.11.22.33.44.nip.io",
"grafanaUrl": "https://grafana.vmi.system.default.11.22.33.44.nip.io",
"keyCloakUrl": "https://keycloak.default.11.22.33.44.nip.io",
"kialiUrl": "https://kiali.vmi.system.default.11.22.33.44.nip.io",
"opensearchUrl": "https://opensearch.vmi.system.default.11.22.33.44.nip.io",
"opensearchDashboardsUrl": "https://opensearchDashboards.vmi.system.default.11.22.33.44.nip.io",
"prometheusUrl": "https://prometheus.vmi.system.default.11.22.33.44.nip.io",
"rancherUrl": "https://rancher.default.11.22.33.44.nip.io"
"thanosQueryUrl": "https://thanos-query.default.172.18.0.231.nip.io"
}
```


## Get consoles credentials

You will need the credentials to access the consoles installed by Verrazzano.

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

## Change the Verrazzano password

To change the Verrazzano password, first change the user password in Keycloak and then update the Verrazzano secret.

**Change the user in Keycloak**

1. Navigate to the Keycloak admin console.

   a. Obtain the Keycloak admin console URL, as described [here](#get-the-consoles-urls).

   b. Obtain the Keycloak admin console credentials, as described [here](#the-keycloak-admin-console).

2. In the left pane, select the `verrazzano-system` realm from the drop-down menu.
3. In the left pane, under `Manage`, select `Users`.
4. In the `Users` pane, search for `verrazzano` or click `View all users`.
5. Select the `verrazzano` user.
6. At the top, select the `Credentials` tab.
7. Click `Reset Password`.
8. Specify the new password and confirm.
9. Specify whether the new password is a temporary password. A temporary password must be reset on next login.
10. Save and confirm the password reset by clicking `Reset password` in the confirmation dialog.

**Update the Verrazzano secret**

Get the base64 encoding for your new password.
{{< clipboard >}}
<div class="highlight">

    $ echo -n '<new password of verrazzano user>' | base64

</div>
{{< /clipboard >}}

Update the password in the secret to replace the existing password value with the new base64 encoded value.
{{< clipboard >}}
<div class="highlight">

    $ kubectl patch secret verrazzano -n verrazzano-system -p '{"data": {"password": "<base64 password of verrazzano user>"}}'

</div>
{{< /clipboard >}}

## Change the Keycloak administrator password

To change the Keycloak administrator password, first change the user password in Keycloak and then update the Keycloak secret.

**Change the administrator user in Keycloak**

1. Navigate to the Keycloak admin console.

   a. Obtain the Keycloak admin console URL, as described [here](#get-the-consoles-urls).

   b. Obtain the Keycloak admin console credentials, as described [here](#the-keycloak-admin-console).

2. In the left pane, select the `master` realm from the drop-down menu.
3. In the left pane, under `Manage`, select `Users`.
4. In the `Users` pane, select the `keycloakadmin` user.
5. At the top, select the `Credentials` tab.
6. Click `Reset password`.
7. Specify the new password and confirm.
8. Specify whether the new password is a temporary password. A temporary password must be reset on next login.
9. Save and confirm the password reset by clicking `Reset password` in the confirmation dialog.

**Update the Keycloak secret**

Get the base64 encoding for your new password.
{{< clipboard >}}
<div class="highlight">

    $ echo -n '<new password for keycloakadmin user>' | base64

</div>
{{< /clipboard >}}

Update the password in the secret to replace the existing password value with the new base64 encoded value.
{{< clipboard >}}
<div class="highlight">

    $ kubectl patch secret keycloak-http -n keycloak -p '{"data": {"password": "<base64 password of keycloakadmin user>"}}'

</div>
{{< /clipboard >}}
