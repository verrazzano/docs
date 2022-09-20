---
title: Access Verrazzano
description: "Information and tools to support operating Verrazzano"
weight: 6
draft: false
aliases:
  - /docs/operations
---

## Get the consoles URLs

Verrazzano installs several consoles. The endpoints for an installation are stored in the `Status` field of the
installed Verrazzano Custom Resource.

You can access the installation endpoints using the [Verrazzano CLI]({{< relref "/docs/setup/install/installation.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/).
See the following respective sections.

{{< tabs tabTotal="2" >}}
{{< tab tabName="vz" >}}
<br>

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
  Version: 1.3.1
  State: Ready
  Profile: dev
  Access Endpoints:
    Console URL: https://verrazzano.default.172.18.0.231.nip.io
    Grafana URL: https://grafana.vmi.system.default.172.18.0.231.nip.io
    Jaeger URL: https://jaeger.default.172.18.0.231.nip.io
    Keycloak URL: https://keycloak.default.172.18.0.231.nip.io
    Kiali URL: https://kiali.vmi.system.default.172.18.0.231.nip.io
    Kibana URL: https://kibana.vmi.system.default.172.18.0.231.nip.io
    OpenSearch URL: https://elasticsearch.vmi.system.default.172.18.0.231.nip.io
    Prometheus URL: https://prometheus.vmi.system.default.172.18.0.231.nip.io
    Rancher URL: https://rancher.default.172.18.0.231.nip.io
```

{{< /tab >}}
{{< tab tabName="kubectl" >}}
<br>

You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:

```shell
$ kubectl get vz -o yaml
```

The resulting output is similar to the following (abbreviated to show only the relevant portions):

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
      consoleUrl: https://verrazzano.default.11.22.33.44.nip.io
      grafanaUrl: https://grafana.vmi.system.default.11.22.33.44.nip.io
      keyCloakUrl: https://keycloak.default.11.22.33.44.nip.io
      kialiUrl: https://kiali.vmi.system.default.11.22.33.44.nip.io
      kibanaUrl: https://kibana.vmi.system.default.11.22.33.44.nip.io
      opensearchUrl: https://elasticsearch.vmi.system.default.11.22.33.44.nip.io
      prometheusUrl: https://prometheus.vmi.system.default.11.22.33.44.nip.io
      rancherUrl: https://rancher.default.11.22.33.44.nip.io
```

If you have `jq` installed, then you can use the following command to get the instance URLs more directly.

`$ kubectl get vz -o jsonpath="{.items[].status.instance}" | jq .`

The following is an example of the output:

```
{
"consoleUrl": "https://verrazzano.default.11.22.33.44.nip.io",
"grafanaUrl": "https://grafana.vmi.system.default.11.22.33.44.nip.io",
"keyCloakUrl": "https://keycloak.default.11.22.33.44.nip.io",
"kialiUrl": "https://kiali.vmi.system.default.11.22.33.44.nip.io",
"opensearchUrl": "https://elasticsearch.vmi.system.default.11.22.33.44.nip.io",
"opensearchDashboardsUrl": "https://kibana.vmi.system.default.11.22.33.44.nip.io",
"prometheusUrl": "https://prometheus.vmi.system.default.11.22.33.44.nip.io",
"rancherUrl": "https://rancher.default.11.22.33.44.nip.io"
}
```

{{< /tab >}}
{{< /tabs >}}

## Get consoles credentials

You will need the credentials to access the consoles installed by Verrazzano.

### Consoles accessed by the same user name

- Grafana
- Prometheus
- OpenSearch Dashboards
- OpenSearch
- Kiali
- Jaeger

**User:** `verrazzano`

To get the password:

```
$ kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo
```

### The Keycloak admin console

**User:** `keycloakadmin`

To get the password:

```
$ kubectl get secret \
    --namespace keycloak keycloak-http \
    -o jsonpath={.data.password} | base64 \
    --decode; echo
```

### The Rancher console

You can log in to the Rancher console using the `verrazzano` user configured in Keycloak or with the local `admin` user for Rancher.
To log in with Keycloak, select the `Log in with Keycloak` link or select the `Use a local user` link to log in with the local user.

**Local Admin User:** `admin`

To get the password:

```
$ kubectl get secret \
    --namespace cattle-system rancher-admin-secret \
    -o jsonpath={.data.password} | base64 \
    --decode; echo
```

**Keycloak User:** `verrazzano`

To get the password:

```
$ kubectl get secret \
    --namespace verrazzano-system verrazzano \
    -o jsonpath={.data.password} | base64 \
    --decode; echo
```

## Change the Verrazzano password

To change the Verrazzano password, first change the user password in Keycloak and then update the Verrazzano secret.

**Change the user in Keycloak**

1. Navigate to the Keycloak admin console.

   a. Obtaining the Keycloak admin console URL is described [here](#get-the-consoles-urls).

   b. Obtaining the Keycloak admin console credentials is described [here](#the-keycloak-admin-console).

1. In the left pane, under `Manage`, select `Users`.
1. In the `Users` pane, search for `verrazzano` or click `View all users`.
1. For the `verrazzano` user, click the `Edit` action.
1. At the top, select the `Credentials` tab.
1. Specify the new password and confirm.
1. Specify whether the new password is a temporary password. A temporary password must be reset on next login.
1. Click `Reset Password`.
1. Confirm the password reset by clicking `Reset password` in the confirmation dialog.

**Update the Verrazzano secret**

Get the base64 encoding for your new password.

`$ echo -n 'MyNewPwd' | base64`

Update the password in the secret.

`$ kubectl edit secret verrazzano -n verrazzano-system`

Replace the existing password value with the new base64 encoded value.
