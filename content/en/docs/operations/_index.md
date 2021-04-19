---
title: Operations
description: "Information and tools to support operating Verrazzano"
weight: 3
draft: false
---
### Get the consoles URLs
Verrazzano installs several consoles. Get the ingress for the consoles with the following command:

`$ kubectl get ingress -A`

To get the URL, prefix `https://` to the host name returned.
For example, `https://rancher.myenv.mydomain.com`.

The following is an example of the ingresses:
```
   NAMESPACE           NAME                               HOSTS                                          ADDRESS          PORTS     AGE
   cattle-system       rancher                            rancher.myenv.mydomain.com                     128.234.33.198   80, 443   93m
   keycloak            keycloak                           keycloak.myenv.mydomain.com                    128.234.33.198   80, 443   69m
   verrazzano-system   verrazzano-operator-ingress        api.myenv.mydomain.com                         128.234.33.198   80, 443   81m
   verrazzano-system   vmi-system-api                     api.vmi.system.myenv.mydomain.com              128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-es-ingest               elasticsearch.vmi.system.myenv.mydomain.com    128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-grafana                 grafana.vmi.system.myenv.mydomain.com          128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-kibana                  kibana.vmi.system.myenv.mydomain.com           128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-prometheus              prometheus.vmi.system.myenv.mydomain.com       128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-prometheus-gw           prometheus-gw.vmi.system.myenv.mydomain.com    128.234.33.198   80, 443   80m
```

### Get console credentials


You will need the credentials to access the consoles installed by Verrazzano.

#### Consoles accessed by the same user name/password
- Grafana
- Prometheus
- Kibana
- Elasticsearch

**User:**  `verrazzano`

To get the password:

`$ kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode; echo`


#### The Keycloak admin console

**User:** `keycloakadmin`

To get the password:  

`$ kubectl get secret --namespace keycloak keycloak-http -o jsonpath={.data.password} | base64 --decode; echo`


#### The Rancher console

**User:** `admin`

To get the password:  

`$ kubectl get secret --namespace cattle-system rancher-admin-secret -o jsonpath={.data.password} | base64 --decode; echo`

#### Change the Verrazzano password

**Change the user in Keycloak**
- Navigate to the Keycloak admin console using directions in this document
- In the left pane, select `Users` which is under `Manage`
- In the `Users` pane, search for `verrazzano` or click the `View all users` button
- For the `verrazzano` user, click the `Edit` action
- Select the `Credentials` tab at the top
- Specify the new password and confirm
- Specify whether the new password is a temporary password. A temporary password must be reset on next login
- Click the `Reset Password` button
- Confirm the password reset by clicking the `Reset password` button in the confirmation popup

**Update the Verrazzano secret**

Get the base64 encoding for your new password:

`echo -n 'MyNewPwd' | base64`

Update the password in the secret:

`kubectl edit secret verrazzano -n verrazzano-system`

Replace the existing password value with the new base64 encoded value
