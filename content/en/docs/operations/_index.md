---
title: Access Verrazzano
description: "Information and tools to support operating Verrazzano"
weight: 5
draft: false
---
## Get the consoles URLs

Verrazzano installs several consoles. The endpoints for an installation are stored in the `Status` field of the
installed Verrazzano Custom Resource. You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:

`$ kubectl get vz -o yaml`

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
      elasticUrl: https://elasticsearch.vmi.system.default.11.22.33.44.nip.io
      grafanaUrl: https://grafana.vmi.system.default.11.22.33.44.nip.io
      keyCloakUrl: https://keycloak.default.11.22.33.44.nip.io
      kibanaUrl: https://kibana.vmi.system.default.11.22.33.44.nip.io
      prometheusUrl: https://prometheus.vmi.system.default.11.22.33.44.nip.io
      rancherUrl: https://rancher.default.11.22.33.44.nip.io
```

If you have `jq` installed, then you can use the following command to get the instance URLs more directly:

`$ kubectl get vz -o jsonpath="{.items[].status.instance}" | jq .`

The following is an example of the output:
```
{
"consoleUrl": "https://verrazzano.default.11.22.33.44.nip.io",
"elasticUrl": "https://elasticsearch.vmi.system.default.11.22.33.44.nip.io",
"grafanaUrl": "https://grafana.vmi.system.default.11.22.33.44.nip.io",
"keyCloakUrl": "https://keycloak.default.11.22.33.44.nip.io",
"kibanaUrl": "https://kibana.vmi.system.default.11.22.33.44.nip.io",
"prometheusUrl": "https://prometheus.vmi.system.default.11.22.33.44.nip.io",
"rancherUrl": "https://rancher.default.11.22.33.44.nip.io"
}
```

## Get consoles credentials

You will need the credentials to access the consoles installed by Verrazzano.

### Consoles accessed by the same user name/password
- Grafana
- Prometheus
- Kibana
- Elasticsearch

**User:**  `verrazzano`

To get the password:

`$ kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode; echo`


### The Keycloak admin console

**User:** `keycloakadmin`

To get the password:  

`$ kubectl get secret --namespace keycloak keycloak-http -o jsonpath={.data.password} | base64 --decode; echo`


### The Rancher console

**User:** `admin`

To get the password:  

`$ kubectl get secret --namespace cattle-system rancher-admin-secret -o jsonpath={.data.password} | base64 --decode; echo`

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

Get the base64 encoding for your new password:

`$ echo -n 'MyNewPwd' | base64`

Update the password in the secret:

`$ kubectl edit secret verrazzano -n verrazzano-system`

Replace the existing password value with the new base64 encoded value.
