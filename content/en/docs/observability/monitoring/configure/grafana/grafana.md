---
title: Customize Grafana
description: Customize Verrazzano Grafana settings
Weight: 5
draft: false
---

By default, Verrazzano automatically installs and configures a Grafana database. However, you can use your own external database.

If you prefer to use your own Grafana database, complete the following steps:

1. Create a secret named `grafana-db` in the `verrazzano-install` namespace which contains the login credentials. For example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ # Load the login credentials into variables
   $ ROOT_SECRET=$(echo <database root user secret> | base64)
   $ USER=$(echo <database user> | base64)
   $ USER_SECRET=$(echo <database user secret> | base64)
   $ #
   $ # Create the secret
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

For more information about the component definition, see [Grafana component]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.GrafanaComponent" >}}) in the Verrazzano custom resource.
