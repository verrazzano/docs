---
title: Customize Grafana
description: Customize Verrazzano Grafana installation settings
linkTitle: Grafana
Weight: 9
draft: false
---


### External Grafana Database

By default, Verrazzano automatically installs and configures a Grafana database, you have the option to use your own external database.  

If you want to provide your own Grafana database , you must:

* Create a secret named `grafana-db` in the `verrazzano-install` namespace which contains the login credentials.

  For example, you can use the `openssl` CLI to create a key pair for the `nip.io` domain.
  ```
  $ export ROOT_SECRET=<The secret for the root user of the database>
  $ export USER=<The login user for the database>
  $ export USER_SECRET=<The secret for the user>
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


Refer to the table in the Verrazzano custom resource pertaining to the [Grafana component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#grafana-component" >}}) for further details.


