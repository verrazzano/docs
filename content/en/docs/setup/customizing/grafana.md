---
title: Customize Grafana
description: Customize Verrazzano Grafana installation settings
linkTitle: Grafana
Weight: 9
draft: false
---


### External Grafana Database

By default, Verrazzano automatically installs and configures a Grafana database, you have the option to use your own external database.  

If you want to provide your own Grafana database , you must do the following steps:

* Create a secret named `grafana-db` in the `verrazzano-install` namespace which contains the login credentials.

  For example, you could configure it as shown:

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
* Configure the Grafana component of the Verrazzano custom resource.

  For example, you could configure it as shown:

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

Refer to the table in the Verrazzano custom resource pertaining to the [Grafana component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#grafana-component" >}}) for further details of the component definition.


