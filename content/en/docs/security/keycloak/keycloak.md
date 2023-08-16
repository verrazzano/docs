---
title: Customize Keycloak and MySQL
Weight: 9
draft: false
aliases:
  - /docs/customize/keycloak
---

### Customize MySQL settings for high availability
* To scale the number of MySQL instances use the [Verrazzano custom resource]({{< relref "docs/reference/vpo-verrazzano-v1beta1.md" >}}), not the MySQL StatefulSet.
Directly modifying the StatefulSet may change the status of the cluster to `ONLINE_PARTIAL`.
* You must have at least one running `mysql-router` to access the MySQL [InnoDB Cluster](https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-introduction.html). Scaling the number of `mysql-router` instances to zero
may result in the [MySQL Operator]({{< relref "docs/reference/vpo-verrazzano-v1beta1.md#install.verrazzano.io/v1beta1.MySQLOperatorComponent" >}}) permanently losing communication with the cluster and Keycloak being unable to communicate with MySQL.
* There are limitations to MySQL group replication policy to provide distributed coordination between servers. See MySQL [Fault-tolerance](https://dev.mysql.com/doc/refman/8.0/en/group-replication-fault-tolerance.html).

For instructions to customize persistent storage settings, see [Customize Persistent Storage]({{< relref "docs/observability/storage.md " >}}).

### Customize MySQL `my.cnf` settings
The file, `my.cnf`, contains the main configuration for MySQL.  You can customize the contents of the  `my.cnf` file by providing overrides to the Keycloak subcomponent MySQL in the Verrazzano custom resource.

For example, you can override the default value of `max_connections` as follows:

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1 
kind: Verrazzano
metadata:
  name: verrazzano
spec:
  profile: dev
  components:
    keycloak:
      mysql:
        overrides:
          - values:
              serverConfig:
                mycnf: |
                  max_connections = 250
```

</div>
{{< /clipboard >}}

The MySQL Operator supports `my.cnf` file configuration overrides only upon installation.  After initial installation, the following steps are required to make changes to the `my.cnf` file.
1. Edit the Verrazzano custom resource and set the overrides for `serverConfig.mycnf` as shown previously in the `max_connections` example.  For example:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl patch verrazzano verrazzano -p '{"spec":{"components":{"keycloak":{"mysql":{"overrides":[{"values": {"serverConfig": {"mycnf": "max_connections = 250\n"}}}]}}}}}' --type=merge
```

</div>
{{< /clipboard >}}
2. Wait for the Verrazzano platform operator to reconcile the changes made to the Verrazzano custom resource.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
```

</div>
{{< /clipboard >}}
3. The MySQL InnoDBCluster object is updated by the Verrazzano platform-operator to contain the `serverConfig.mycnf` overrides.  You can use the following command to view the contents of the InnoDBCluster object.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get innodbcluster -n keycloak mysql -o yaml
```

</div>
{{< /clipboard >}}
4. Edit the `mysql-initconf` ConfigMap in the  `keycloak` namespace and update the settings in the `99-extra.cnf` section. For example:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl patch configmap -n keycloak mysql-initconf -p \
'{"data":{"99-extra.cnf": "# Additional user configurations taken from spec.mycnf in InnoDBCluster.\n# Do not edit directly.\n[mysqld]\nmax_connections = 250\n"}}' \
 --type=merge
```

</div>
{{< /clipboard >}}
Example snippet of the `99-extra.cnf` portion of the ConfigMap after the patch.
{{< clipboard >}}
<div class="highlight">

```
  99-extra.cnf: |
    # Additional user configurations taken from spec.mycnf in InnoDBCluster.
    # Do not edit directly.
    [mysqld]
    max_connections = 250
```

</div>
{{< /clipboard >}}
5. Start a rollout restart of the MySQL StatefulSet. After the rollout restart completes, the MySQL pods will be using the configuration overrides.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl rollout restart -n keycloak statefulset mysql
```

</div>
{{< /clipboard >}}
6. Wait for the rollout restart of the MySQL StatefulSet to complete.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n keycloak rollout status statefulset/mysql
```

</div>
{{< /clipboard >}}
