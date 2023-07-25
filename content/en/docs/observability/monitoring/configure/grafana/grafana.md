---
title: Customize Grafana
Weight: 5
draft: false
aliases:
  - /docs/customize/grafana
---

### Configure a Grafana database

By default, Verrazzano automatically installs and configures a Grafana database. However, you can use your own external database.

If you prefer to use your own Grafana database, complete the following steps:

1. Create a secret named `grafana-db` in the `verrazzano-install` namespace which contains the login credentials. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ ROOT_SECRET=$(echo <database root user secret> | base64)
   $ USER=$(echo <database user> | base64)
   $ USER_SECRET=$(echo <database user secret> | base64)
   $ kubectl apply -f - <<-EOF
   apiVersion: v1
   kind: Secret
   metadata:
     name: grafana-db
     namespace: verrazzano-install
   type: Opaque
   data:
     root-password: $ROOT_SECRET
     username: $USER
     password: $USER_SECRET
   EOF
   ```

</div>
{{< /clipboard >}}

1. Configure the Grafana component of the Verrazzano custom resource. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   apiVersion: install.verrazzano.io/v1beta1
   kind: Verrazzano
   metadata:
     name: grafana-db-example
   spec:
     profile: dev
     components:
       grafana:
         database:
           host: mysql.verrazzano-install.svc.cluster.local
           name: grafana
   ```

</div>
{{< /clipboard >}}

### Configure an SMTP server

To configure Grafana to send SMTP notifications, complete the following steps:

1. Create a secret named `smtp-secret` in the `verrazzano-system` namespace which contains the SMTP server credentials. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-system create secret generic smtp-secret \
    --from-literal=username="<smtp server username>" \
    --from-literal=password="<smtp server password>" \
    --from-file=cert=<path to file containing certificate> \
    --from-file=key=<path to file containing certificate key>
   ```

</div>
{{< /clipboard >}}

1. Configure the Grafana component of the Verrazzano custom resource. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   apiVersion: install.verrazzano.io/v1beta1
   kind: Verrazzano
   metadata:
     name: grafana-smtp-example
   spec:
     profile: dev
     components:
       grafana:
         smtp:
           certFileKey: "cert"
           ehloIdentity: "<Name to be used as client identity for EHLO in SMTP dialog>"
           enabled: true
           existingSecret: "smtp-secret"
           fromAddress: "<Address used when sending out emails>"
           fromName: "<Name to be used when sending out emails>"
           host: "<host or host:port for the smtp server>"
           passwordKey: "password"
           skipVerify: true
           startTLSPolicy: ""
           userKey: "username"
           keyFileKey: "key"
   ```

</div>
{{< /clipboard >}}

For more information about Grafana SMTP configurations, see the [Grafana Documentation](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#smtp).

For more information about the component definition, see [Grafana component]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.GrafanaComponent" >}}) in the Verrazzano custom resource.
