---
title: Customize Keycloak and MySQL
description: Customize Verrazzano Keycloak and MySQL settings for high availability
Weight: 9
draft: false
aliases:
  - /docs/customize/keycloak
  - /docs/security/keycloak/keycloak
---

* To scale the number of MySQL instances use the [Verrazzano Custom Resource]({{< relref "docs/reference/vpo-verrazzano-v1beta1.md" >}}), not the MySQL StatefulSet.
Directly modifying the StatefulSet may change the status of the cluster to `ONLINE_PARTIAL`.
* You must have at least one running `mysql-router` to access the MySQL [InnoDB Cluster](https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-introduction.html). Scaling the number of `mysql-router` instances to zero
may result in the [MySQL Operator]({{< relref "docs/reference/vpo-verrazzano-v1beta1.md#install.verrazzano.io/v1beta1.MySQLOperatorComponent" >}}) permanently losing communication with the cluster and Keycloak being unable to communicate with MySQL.
* There are limitations to MySQL group replication policy to provide distributed coordination between servers. See [MySQL Fault-tolerance](https://dev.mysql.com/doc/refman/8.0/en/group-replication-fault-tolerance.html).

For instructions to customize persistent storage settings, see [Customize Persistent Storage]({{< relref "docs/observability/logging/configure-opensearch/storage.md " >}}).
