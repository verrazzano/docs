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

  ```
  $ # Load the login credentials into variables
  $ ROOT_SECRET=<The secret for the root user of the database>
  $ USER=<The login user for the database>
  $ USER_SECRET=<The secret for the user>
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

Refer to the table in the Verrazzano custom resource pertaining to the [Grafana component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#grafana-component" >}}) for further details of the component definition.


