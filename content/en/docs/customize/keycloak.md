---
title: Customize Keycloak/MySQL
description: Customize Verrazzano Keycloak/MySQL settings
linkTitle: Keycloak/MySQL
Weight: 6
draft: false
---

### MySQL in a high availability environment

* Scaling the number of MySQL instances should be done via the [Verrazzano Custom Resource]({{< relref "docs/reference/api/verrazzano/v1beta1.md" >}}), not via the MySQL StatefulSet. Modifying the StatefulSet directly may result in
the status of the cluster to be `ONLINE_PARTIAL`.
* You must keep at  least one running `mysql-router` to have access to the MySQL [InnoDB Cluster](https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-introduction.html). Scaling the number of `mysql-router` instances to 0
may result in the [MySQL Operator]({{< relref "docs/reference/api/verrazzano/v1beta1.md#mysql-operator-component" >}}) permanently losing communication with the cluster and Keycloak being unable to communicate with MySQL.
* Limitations to MySQL group replication policy in order to provide distributed coordination between servers is defined here: [MySQL Fault-tolerance](https://dev.mysql.com/doc/refman/8.0/en/group-replication-fault-tolerance.html).